// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/scripthashindex.h>

#include <chain.h>
#include <coins.h>
#include <common/args.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <dbwrapper.h>
#include <flatfile.h>
#include <index/base.h>
#include <interfaces/chain.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ios>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
constexpr uint8_t DB_FUNDING{'F'};
constexpr uint8_t DB_SPENDING{'S'};
constexpr size_t DB_PREFIX_SIZE{8};

std::unique_ptr<ScriptHashIndex> g_scripthashindex;

uint256 ComputeScriptHashIndexHash(const CScript& script)
{
    uint256 hash;
    CSHA256().Write(script.data(), script.size()).Finalize(hash.begin());
    std::reverse(hash.begin(), hash.end());
    return hash;
}

namespace {

using DBPrefix = std::array<unsigned char, DB_PREFIX_SIZE>;

static DBPrefix ScriptHashPrefix(const uint256& scripthash)
{
    DBPrefix result{};
    std::copy_n(scripthash.begin(), DB_PREFIX_SIZE, result.begin());
    return result;
}

struct CompactOutpointPrefix {
    uint64_t txid_prefix;
    uint32_t n;

    friend bool operator==(const CompactOutpointPrefix& a, const CompactOutpointPrefix& b)
    {
        return a.txid_prefix == b.txid_prefix && a.n == b.n;
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata64(s, txid_prefix);
        ser_writedata32be(s, n);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        txid_prefix = ser_readdata64(s);
        n = ser_readdata32be(s);
    }
};

static CompactOutpointPrefix MakeCompactOutpointPrefix(const COutPoint& outpoint)
{
    // Keep the txid prefix and vout separate so the compact key only collides
    // when the truncated txid itself collides, instead of also folding in n.
    return {ReadBE64(outpoint.hash.begin()), outpoint.n};
}

struct FundingKey {
    DBPrefix scripthash_prefix;
    uint32_t height;
    uint32_t tx_pos;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_FUNDING);
        s.write(std::as_bytes(std::span{scripthash_prefix}));
        ser_writedata32be(s, height);
        ser_writedata32be(s, tx_pos);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_FUNDING) {
            throw std::ios_base::failure("Invalid format for scripthash index funding key");
        }
        s.read(std::as_writable_bytes(std::span{scripthash_prefix}));
        height = ser_readdata32be(s);
        tx_pos = ser_readdata32be(s);
    }
};

struct FundingKeyPrefix {
    DBPrefix scripthash_prefix;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_FUNDING);
        s.write(std::as_bytes(std::span{scripthash_prefix}));
    }
};

struct SpendingKey {
    CompactOutpointPrefix outpoint_prefix;
    uint32_t height;
    uint32_t tx_pos;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_SPENDING);
        outpoint_prefix.Serialize(s);
        ser_writedata32be(s, height);
        ser_writedata32be(s, tx_pos);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_SPENDING) {
            throw std::ios_base::failure("Invalid format for scripthash index spending key");
        }
        outpoint_prefix.Unserialize(s);
        height = ser_readdata32be(s);
        tx_pos = ser_readdata32be(s);
    }
};

struct SpendingKeyPrefix {
    CompactOutpointPrefix outpoint_prefix;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_SPENDING);
        outpoint_prefix.Serialize(s);
    }
};

struct TxPosition {
    FlatFilePos block_pos;
    uint32_t height;
    uint32_t tx_pos;

    friend bool operator<(const TxPosition& a, const TxPosition& b)
    {
        if (a.height != b.height) return a.height < b.height;
        if (a.tx_pos != b.tx_pos) return a.tx_pos < b.tx_pos;
        if (a.block_pos.nFile != b.block_pos.nFile) return a.block_pos.nFile < b.block_pos.nFile;
        return a.block_pos.nPos < b.block_pos.nPos;
    }
};

struct BlockPosLess {
    bool operator()(const FlatFilePos& a, const FlatFilePos& b) const
    {
        return a.nFile < b.nFile || (a.nFile == b.nFile && a.nPos < b.nPos);
    }
};

using BlockCache = std::map<FlatFilePos, CBlock, BlockPosLess>;

template <uint8_t PREFIX>
struct DBPrefixKey {
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, PREFIX);
    }
};

struct ScriptHashColdScan {
    std::map<TxPosition, Txid> funding_history;
    std::unordered_map<COutPoint, ScriptHashUtxo, SaltedOutpointHasher> funded_utxos;
    std::set<TxPosition> spending_positions;
};

static const CBlock* GetBlockAtDiskPos(const Chainstate& chainstate, const FlatFilePos& block_pos, BlockCache& block_cache)
{
    const auto found{block_cache.find(block_pos)};
    if (found != block_cache.end()) return &found->second;

    CBlock block;
    if (!chainstate.m_blockman.ReadBlock(block, block_pos, std::nullopt)) return nullptr;
    return &block_cache.emplace(block_pos, std::move(block)).first->second;
}

static bool ReadTxByPosition(const Chainstate& chainstate, const TxPosition& position, BlockCache& block_cache, CTransactionRef& tx)
{
    const CBlock* block{GetBlockAtDiskPos(chainstate, position.block_pos, block_cache)};
    if (!block) return false;
    if (position.tx_pos >= block->vtx.size()) return false;
    tx = block->vtx[position.tx_pos];
    return true;
}

struct ScriptHashUtxoScanResult {
    std::vector<ScriptHashUtxo> utxos;
    CAmount balance{0};
};

struct ScriptHashHistoryHasher {
    size_t operator()(const ScriptHashHistory& history) const
    {
        return SaltedUint256Hasher{}(history.txid.ToUint256()) ^ static_cast<size_t>(history.height);
    }
};

struct CacheUpdate {
    std::vector<ScriptHashHistory> history_to_add;
    std::vector<ScriptHashHistory> history_to_remove;
    std::vector<ScriptHashUtxo> utxos_to_add;
    std::vector<COutPoint> utxos_to_remove;
    CAmount balance_delta{0};
};

using CacheUpdates = std::unordered_map<uint256, CacheUpdate, SaltedUint256Hasher>;

static FlatFilePos GetBlockDiskPos(const interfaces::BlockInfo& block)
{
    assert(block.file_number >= 0);
    return {block.file_number, block.data_pos};
}

static ScriptHashColdScan ScanScriptHash(const Chainstate& chainstate, CDBWrapper& db, const uint256& scripthash)
{
    BlockCache block_cache;
    ScriptHashColdScan result;

    // One LevelDB iterator gives the whole cold query a stable DB snapshot.
    // Combined with block positions stored in the row values, this avoids
    // mixing old index rows with whichever chain happens to be active mid-scan.
    std::unique_ptr<CDBIterator> funding_it(db.NewIterator());
    FundingKey funding_key{};
    const DBPrefix scripthash_prefix{ScriptHashPrefix(scripthash)};
    funding_it->Seek(FundingKeyPrefix{scripthash_prefix});

    while (funding_it->Valid() && funding_it->GetKey(funding_key) && funding_key.scripthash_prefix == scripthash_prefix) {
        FlatFilePos block_pos;
        if (!funding_it->GetValue(block_pos)) {
            funding_it->Next();
            continue;
        }
        const TxPosition tx_pos{block_pos, funding_key.height, funding_key.tx_pos};
        CTransactionRef tx;
        if (ReadTxByPosition(chainstate, tx_pos, block_cache, tx)) {
            const Txid txid{tx->GetHash()};
            bool matched{false};
            for (uint32_t i = 0; i < tx->vout.size(); ++i) {
                const CTxOut& tx_out{tx->vout[i]};
                if (tx_out.scriptPubKey.IsUnspendable()) continue;
                if (ComputeScriptHashIndexHash(tx_out.scriptPubKey) != scripthash) continue;
                const COutPoint outpoint{txid, i};
                result.funded_utxos.emplace(outpoint, ScriptHashUtxo{outpoint, static_cast<int>(funding_key.height), tx_out.nValue});
                matched = true;
            }
            if (matched) result.funding_history.try_emplace(tx_pos, txid);
        }
        funding_it->Next();
    }

    SpendingKey spending_key{};
    for (const auto& [outpoint, _] : result.funded_utxos) {
        const CompactOutpointPrefix outpoint_prefix{MakeCompactOutpointPrefix(outpoint)};
        funding_it->Seek(SpendingKeyPrefix{outpoint_prefix});
        while (funding_it->Valid() && funding_it->GetKey(spending_key) && spending_key.outpoint_prefix == outpoint_prefix) {
            FlatFilePos block_pos;
            if (funding_it->GetValue(block_pos)) {
                result.spending_positions.insert({block_pos, spending_key.height, spending_key.tx_pos});
            }
            funding_it->Next();
        }
    }

    return result;
}

static std::vector<ScriptHashHistory> BuildScriptHashHistory(const Chainstate& chainstate, const ScriptHashColdScan& scan)
{
    BlockCache block_cache;
    std::map<TxPosition, Txid> history_entries{scan.funding_history.begin(), scan.funding_history.end()};

    // History queries only need exact prevout membership, not values or the
    // surviving UTXO set, so build on the shared cold scan rather than
    // repeating the funding walk with slightly different logic.
    for (const TxPosition& tx_pos : scan.spending_positions) {
        CTransactionRef tx;
        if (!ReadTxByPosition(chainstate, tx_pos, block_cache, tx)) continue;

        for (const auto& txin : tx->vin) {
            if (!scan.funded_utxos.contains(txin.prevout)) continue;
            history_entries.try_emplace(tx_pos, tx->GetHash());
            break;
        }
    }

    std::vector<ScriptHashHistory> result;
    result.reserve(history_entries.size());
    for (const auto& [pos, txid] : history_entries) {
        result.push_back({txid, static_cast<int>(pos.height)});
    }
    return result;
}

static ScriptHashUtxoScanResult BuildScriptHashUtxos(const Chainstate& chainstate, const ScriptHashColdScan& scan)
{
    BlockCache block_cache;
    std::unordered_set<COutPoint, SaltedOutpointHasher> spent_outpoints;
    for (const TxPosition& tx_pos : scan.spending_positions) {
        CTransactionRef tx;
        if (!ReadTxByPosition(chainstate, tx_pos, block_cache, tx)) continue;

        for (const auto& txin : tx->vin) {
            if (!scan.funded_utxos.contains(txin.prevout)) continue;
            spent_outpoints.insert(txin.prevout);
        }
    }

    ScriptHashUtxoScanResult result;
    result.utxos.reserve(scan.funded_utxos.size());
    for (const auto& [outpoint, utxo] : scan.funded_utxos) {
        if (spent_outpoints.contains(outpoint)) continue;
        result.balance += utxo.value;
        result.utxos.push_back(utxo);
    }
    std::sort(result.utxos.begin(), result.utxos.end(), [](const ScriptHashUtxo& a, const ScriptHashUtxo& b) {
        return a.outpoint < b.outpoint;
    });
    return result;
}

} // namespace

void ScriptHashIndex::PruneUnpinnedCacheEntries()
{
    for (auto it = m_cache.begin(); it != m_cache.end();) {
        if (m_pinned_refs.contains(it->first)) {
            ++it;
            continue;
        }
        it = m_cache.erase(it);
    }
}

void ScriptHashIndex::ApplyBlockAppendCacheUpdates(const interfaces::BlockInfo& block)
{
    assert(block.data);

    CacheUpdates updates;
    const auto& txs = block.data->vtx;
    const auto* undo_data = block.undo_data;
    const int height{block.height};
    if (txs.size() > 1) {
        assert(undo_data && undo_data->vtxundo.size() == txs.size() - 1);
    }

    for (size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs[i];
        const Txid txid{tx->GetHash()};
        std::unordered_set<uint256, SaltedUint256Hasher> touched_scripthashes;

        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            const CTxOut& tx_out{tx->vout[n]};
            if (tx_out.scriptPubKey.IsUnspendable()) continue;

            const uint256 scripthash{ComputeScriptHashIndexHash(tx_out.scriptPubKey)};
            auto& update{updates[scripthash]};
            update.utxos_to_add.push_back({COutPoint{txid, n}, height, tx_out.nValue});
            update.balance_delta += tx_out.nValue;
            if (touched_scripthashes.insert(scripthash).second) {
                update.history_to_add.push_back({txid, height});
            }
        }

        if (tx->IsCoinBase()) continue;

        const auto& tx_undo{undo_data->vtxundo.at(i - 1)};
        assert(tx_undo.vprevout.size() == tx->vin.size());

        for (size_t j = 0; j < tx->vin.size(); ++j) {
            const Coin& spent_coin{tx_undo.vprevout[j]};
            if (spent_coin.out.scriptPubKey.IsUnspendable()) continue;

            const uint256 scripthash{ComputeScriptHashIndexHash(spent_coin.out.scriptPubKey)};
            auto& update{updates[scripthash]};
            update.utxos_to_remove.push_back(tx->vin[j].prevout);
            update.balance_delta -= spent_coin.out.nValue;
            if (touched_scripthashes.insert(scripthash).second) {
                update.history_to_add.push_back({txid, height});
            }
        }
    }

    LOCK(m_cache_mutex);
    PruneUnpinnedCacheEntries();
    for (const auto& [scripthash, update] : updates) {
        const auto it{m_cache.find(scripthash)};
        if (it == m_cache.end()) continue;

        CacheEntry& entry{it->second};
        if (entry.history_loaded) {
            entry.history.insert(entry.history.end(), update.history_to_add.begin(), update.history_to_add.end());
        }
        // Leave unloaded spendable state cold; a later GetUtxos/GetBalance call
        // can reconstruct it from the compact on-disk index.
        if (!entry.utxos_loaded) continue;

        for (const COutPoint& outpoint : update.utxos_to_remove) {
            std::erase_if(entry.utxos, [&](const ScriptHashUtxo& utxo) {
                return utxo.outpoint == outpoint;
            });
        }
        entry.utxos.insert(entry.utxos.end(), update.utxos_to_add.begin(), update.utxos_to_add.end());
        std::sort(entry.utxos.begin(), entry.utxos.end(), [](const ScriptHashUtxo& a, const ScriptHashUtxo& b) {
            return a.outpoint < b.outpoint;
        });
        entry.balance += update.balance_delta;
    }
}

void ScriptHashIndex::ApplyBlockRemoveCacheUpdates(const interfaces::BlockInfo& block)
{
    assert(block.data);

    CacheUpdates updates;
    const auto& txs = block.data->vtx;
    const auto* undo_data = block.undo_data;
    const int height{block.height};
    if (txs.size() > 1) {
        assert(undo_data && undo_data->vtxundo.size() == txs.size() - 1);
    }

    for (size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs[i];
        const Txid txid{tx->GetHash()};
        std::unordered_set<uint256, SaltedUint256Hasher> touched_scripthashes;

        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            const CTxOut& tx_out{tx->vout[n]};
            if (tx_out.scriptPubKey.IsUnspendable()) continue;

            const uint256 scripthash{ComputeScriptHashIndexHash(tx_out.scriptPubKey)};
            auto& update{updates[scripthash]};
            update.utxos_to_remove.emplace_back(txid, n);
            update.balance_delta -= tx_out.nValue;
            if (touched_scripthashes.insert(scripthash).second) {
                update.history_to_remove.push_back({txid, height});
            }
        }

        if (tx->IsCoinBase()) continue;

        const auto& tx_undo{undo_data->vtxundo.at(i - 1)};
        assert(tx_undo.vprevout.size() == tx->vin.size());

        for (size_t j = 0; j < tx->vin.size(); ++j) {
            const Coin& spent_coin{tx_undo.vprevout[j]};
            if (spent_coin.out.scriptPubKey.IsUnspendable()) continue;

            const uint256 scripthash{ComputeScriptHashIndexHash(spent_coin.out.scriptPubKey)};
            auto& update{updates[scripthash]};
            update.utxos_to_add.push_back({tx->vin[j].prevout, static_cast<int>(spent_coin.nHeight), spent_coin.out.nValue});
            update.balance_delta += spent_coin.out.nValue;
            if (touched_scripthashes.insert(scripthash).second) {
                update.history_to_remove.push_back({txid, height});
            }
        }
    }

    LOCK(m_cache_mutex);
    PruneUnpinnedCacheEntries();
    for (const auto& [scripthash, update] : updates) {
        const auto it{m_cache.find(scripthash)};
        if (it == m_cache.end()) continue;

        CacheEntry& entry{it->second};
        if (entry.history_loaded && !update.history_to_remove.empty()) {
            const std::unordered_set<ScriptHashHistory, ScriptHashHistoryHasher> history_to_remove{
                update.history_to_remove.begin(), update.history_to_remove.end()};
            std::erase_if(entry.history, [&](const ScriptHashHistory& history) {
                return history_to_remove.contains(history);
            });
        }
        if (!entry.utxos_loaded) continue;

        for (const COutPoint& outpoint : update.utxos_to_remove) {
            std::erase_if(entry.utxos, [&](const ScriptHashUtxo& utxo) {
                return utxo.outpoint == outpoint;
            });
        }
        entry.utxos.insert(entry.utxos.end(), update.utxos_to_add.begin(), update.utxos_to_add.end());
        std::sort(entry.utxos.begin(), entry.utxos.end(), [](const ScriptHashUtxo& a, const ScriptHashUtxo& b) {
            return a.outpoint < b.outpoint;
        });
        entry.balance += update.balance_delta;
    }
}

ScriptHashIndex::ScriptHashIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "scripthashindex"),
      m_db{std::make_unique<DB>(gArgs.GetDataDirNet() / "indexes" / "scripthashindex" / "db", n_cache_size, f_memory, f_wipe)}
{
}

interfaces::Chain::NotifyOptions ScriptHashIndex::CustomOptions()
{
    interfaces::Chain::NotifyOptions options;
    options.connect_undo_data = true;
    options.disconnect_data = true;
    options.disconnect_undo_data = true;
    return options;
}

bool ScriptHashIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    CDBBatch batch(*m_db);
    const auto& txs = block.data->vtx;
    const FlatFilePos block_pos{GetBlockDiskPos(block)};

    for (size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs[i];
        const uint32_t height{static_cast<uint32_t>(block.height)};
        const uint32_t tx_pos{static_cast<uint32_t>(i)};

        for (const CTxOut& tx_out : tx->vout) {
            if (tx_out.scriptPubKey.IsUnspendable()) continue;
            const auto sh_prefix{ScriptHashPrefix(ComputeScriptHashIndexHash(tx_out.scriptPubKey))};
            // Store the block disk location in the row value so cold reads can
            // reconstruct from immutable block data without depending on the
            // current active-chain block at this height.
            batch.Write(FundingKey{sh_prefix, height, tx_pos}, block_pos);
        }

        if (tx->IsCoinBase()) continue;
        for (const CTxIn& txin : tx->vin) {
            batch.Write(SpendingKey{MakeCompactOutpointPrefix(txin.prevout), height, tx_pos}, block_pos);
        }
    }

    LOCK(m_scan_mutex);
    m_db->WriteBatch(batch);
    ApplyBlockAppendCacheUpdates(block);
    return true;
}

bool ScriptHashIndex::CustomRemove(const interfaces::BlockInfo& block)
{
    CDBBatch batch(*m_db);
    assert(block.data);
    const auto& txs = block.data->vtx;

    for (size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs[i];
        const uint32_t height{static_cast<uint32_t>(block.height)};
        const uint32_t tx_pos{static_cast<uint32_t>(i)};

        for (const CTxOut& tx_out : tx->vout) {
            if (tx_out.scriptPubKey.IsUnspendable()) continue;
            const auto sh_prefix{ScriptHashPrefix(ComputeScriptHashIndexHash(tx_out.scriptPubKey))};
            batch.Erase(FundingKey{sh_prefix, height, tx_pos});
        }

        if (tx->IsCoinBase()) continue;
        for (const CTxIn& txin : tx->vin) {
            batch.Erase(SpendingKey{MakeCompactOutpointPrefix(txin.prevout), height, tx_pos});
        }
    }

    LOCK(m_scan_mutex);
    m_db->WriteBatch(batch);
    ApplyBlockRemoveCacheUpdates(block);
    return true;
}

BaseIndex::DB& ScriptHashIndex::GetDB() const { return *m_db; }

std::vector<ScriptHashHistory> ScriptHashIndex::GetHistory(const uint256& scripthash) const
{
    {
        LOCK(m_cache_mutex);
        const auto it{m_cache.find(scripthash)};
        if (it != m_cache.end() && it->second.history_loaded) return it->second.history;
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        LOCK(m_scan_mutex);
        const CBlockIndex* scan_tip{GetBestBlockIndex()};
        const auto scan{ScanScriptHash(*m_chainstate, *m_db, scripthash)};
        auto history{BuildScriptHashHistory(*m_chainstate, scan)};

        // Only publish cold query results when the index tip stayed fixed for
        // the whole scan. Otherwise retry once and fall back to an uncached
        // best-effort result under sustained churn.
        if (GetBestBlockIndex() != scan_tip) {
            if (attempt == 0) continue;
            return history;
        }

        LOCK(m_cache_mutex);
        CacheEntry& entry{m_cache[scripthash]};
        if (!entry.history_loaded) {
            entry.history = std::move(history);
            entry.history_loaded = true;
        }
        return entry.history;
    }

    Assume(false);
    return {};
}

std::vector<ScriptHashUtxo> ScriptHashIndex::GetUtxos(const uint256& scripthash) const
{
    {
        LOCK(m_cache_mutex);
        const auto it{m_cache.find(scripthash)};
        if (it != m_cache.end() && it->second.utxos_loaded) return it->second.utxos;
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        LOCK(m_scan_mutex);
        const CBlockIndex* scan_tip{GetBestBlockIndex()};
        const auto scan{ScanScriptHash(*m_chainstate, *m_db, scripthash)};
        auto scan_result{BuildScriptHashUtxos(*m_chainstate, scan)};

        if (GetBestBlockIndex() != scan_tip) {
            if (attempt == 0) continue;
            return scan_result.utxos;
        }

        LOCK(m_cache_mutex);
        CacheEntry& entry{m_cache[scripthash]};
        if (!entry.utxos_loaded) {
            entry.utxos = std::move(scan_result.utxos);
            entry.balance = scan_result.balance;
            entry.utxos_loaded = true;
        }
        return entry.utxos;
    }

    Assume(false);
    return {};
}

CAmount ScriptHashIndex::GetBalance(const uint256& scripthash) const
{
    {
        LOCK(m_cache_mutex);
        const auto it{m_cache.find(scripthash)};
        if (it != m_cache.end() && it->second.utxos_loaded) return it->second.balance;
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        LOCK(m_scan_mutex);
        const CBlockIndex* scan_tip{GetBestBlockIndex()};
        const auto scan{ScanScriptHash(*m_chainstate, *m_db, scripthash)};
        auto scan_result{BuildScriptHashUtxos(*m_chainstate, scan)};

        if (GetBestBlockIndex() != scan_tip) {
            if (attempt == 0) continue;
            return scan_result.balance;
        }

        LOCK(m_cache_mutex);
        CacheEntry& entry{m_cache[scripthash]};
        if (!entry.utxos_loaded) {
            entry.utxos = std::move(scan_result.utxos);
            entry.balance = scan_result.balance;
            entry.utxos_loaded = true;
        }
        return entry.balance;
    }

    Assume(false);
    return 0;
}

ScriptHashActivity ScriptHashIndex::GetActivity(const uint256& scripthash) const
{
    LOCK(m_scan_mutex);
    const CBlockIndex* scan_tip{GetBestBlockIndex()};
    {
        LOCK(m_cache_mutex);
        const auto it{m_cache.find(scripthash)};
        if (it != m_cache.end() && it->second.history_loaded && it->second.utxos_loaded) {
            return {it->second.history, it->second.utxos, it->second.balance, scan_tip ? scan_tip->GetBlockHash() : uint256{}, scan_tip ? scan_tip->nHeight : -1};
        }
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        scan_tip = GetBestBlockIndex();
        const auto scan{ScanScriptHash(*m_chainstate, *m_db, scripthash)};
        auto history{BuildScriptHashHistory(*m_chainstate, scan)};
        auto scan_result{BuildScriptHashUtxos(*m_chainstate, scan)};

        if (GetBestBlockIndex() != scan_tip) {
            if (attempt == 0) continue;
            return {std::move(history), std::move(scan_result.utxos), scan_result.balance, scan_tip ? scan_tip->GetBlockHash() : uint256{}, scan_tip ? scan_tip->nHeight : -1};
        }

        LOCK(m_cache_mutex);
        CacheEntry& entry{m_cache[scripthash]};
        if (!entry.history_loaded) {
            entry.history = std::move(history);
            entry.history_loaded = true;
        }
        if (!entry.utxos_loaded) {
            entry.utxos = std::move(scan_result.utxos);
            entry.balance = scan_result.balance;
            entry.utxos_loaded = true;
        }
        return {entry.history, entry.utxos, entry.balance, scan_tip ? scan_tip->GetBlockHash() : uint256{}, scan_tip ? scan_tip->nHeight : -1};
    }

    Assume(false);
    return {};
}

void ScriptHashIndex::CacheScriptHash(const uint256& scripthash)
{
    {
        LOCK(m_cache_mutex);
        ++m_pinned_refs[scripthash];
    }
    // Pinning keeps already-loaded state warm across tip changes, but avoids
    // eagerly materializing UTXOs/balance for history-only subscribers.
}

void ScriptHashIndex::UncacheScriptHash(const uint256& scripthash)
{
    LOCK(m_cache_mutex);
    const auto ref_it{m_pinned_refs.find(scripthash)};
    if (ref_it == m_pinned_refs.end()) return;
    if (ref_it->second > 1) {
        --ref_it->second;
        return;
    }
    m_pinned_refs.erase(ref_it);
    m_cache.erase(scripthash);
}
