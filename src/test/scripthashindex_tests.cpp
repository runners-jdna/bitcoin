// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/scripthashindex.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(scripthashindex_tests)

namespace {

static CMutableTransaction CreateSpendTx(const CTransactionRef& prev_tx, const CScript& prev_spk, const CScript& dest_spk, CKey& signing_key)
{
    CMutableTransaction spend_tx;
    spend_tx.version = 1;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout = COutPoint(prev_tx->GetHash(), 0);
    spend_tx.vout.resize(1);
    spend_tx.vout[0].nValue = prev_tx->vout.at(0).nValue;
    spend_tx.vout[0].scriptPubKey = dest_spk;

    std::vector<unsigned char> vchSig;
    const uint256 hash = SignatureHash(prev_spk, spend_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    signing_key.Sign(hash, vchSig);
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    spend_tx.vin[0].scriptSig << vchSig;
    return spend_tx;
}

} // namespace

BOOST_FIXTURE_TEST_CASE(scripthashindex_initial_sync, TestChain100Setup)
{
    ScriptHashIndex index(interfaces::MakeChain(m_node), 1 << 20, true);
    BOOST_REQUIRE(index.Init());

    const CScript coinbase_spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    const uint256 coinbase_sh = ComputeScriptHashIndexHash(coinbase_spk);

    for (int i = 0; i < 50; i++) {
        std::vector<CMutableTransaction> no_txns;
        CreateAndProcessBlock(no_txns, coinbase_spk);
    }

    CScript dest_spk = CScript() << OP_TRUE;
    const uint256 dest_sh = ComputeScriptHashIndexHash(dest_spk);
    CMutableTransaction spend_tx{CreateSpendTx(m_coinbase_txns[0], coinbase_spk, dest_spk, coinbaseKey)};

    CreateAndProcessBlock({spend_tx}, coinbase_spk);

    BOOST_CHECK(!index.BlockUntilSyncedToCurrentChain());

    index.Sync();

    auto history = index.GetHistory(coinbase_sh);
    BOOST_CHECK(!history.empty());

    auto dest_history = index.GetHistory(dest_sh);
    BOOST_CHECK_EQUAL(dest_history.size(), 1U);
    BOOST_CHECK(dest_history[0].txid == spend_tx.GetHash());

    auto dest_utxos = index.GetUtxos(dest_sh);
    BOOST_CHECK_EQUAL(dest_utxos.size(), 1U);
    BOOST_CHECK(dest_utxos[0].outpoint.hash == spend_tx.GetHash());
    BOOST_CHECK_EQUAL(dest_utxos[0].outpoint.n, 0U);
    BOOST_CHECK_EQUAL(dest_utxos[0].value, m_coinbase_txns[0]->GetValueOut());

    BOOST_CHECK_EQUAL(index.GetBalance(dest_sh), m_coinbase_txns[0]->GetValueOut());

    auto coinbase_utxos = index.GetUtxos(coinbase_sh);
    for (const auto& utxo : coinbase_utxos) {
        BOOST_CHECK(!(utxo.outpoint.hash == m_coinbase_txns[0]->GetHash() && utxo.outpoint.n == 0));
    }

    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    index.Stop();
}

BOOST_FIXTURE_TEST_CASE(scripthashindex_reorg_rollback, TestChain100Setup)
{
    ScriptHashIndex index(interfaces::MakeChain(m_node), 1 << 20, true);
    BOOST_REQUIRE(index.Init());

    const CScript coinbase_spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    const uint256 coinbase_sh = ComputeScriptHashIndexHash(coinbase_spk);

    for (int i = 0; i < 50; i++) {
        CreateAndProcessBlock({}, coinbase_spk);
    }

    CScript dest_spk = CScript() << OP_TRUE;
    const uint256 dest_sh = ComputeScriptHashIndexHash(dest_spk);
    CMutableTransaction spend_tx{CreateSpendTx(m_coinbase_txns[0], coinbase_spk, dest_spk, coinbaseKey)};

    CBlock spend_block = CreateAndProcessBlock({spend_tx}, coinbase_spk);
    BOOST_CHECK(!index.BlockUntilSyncedToCurrentChain());
    index.Sync();

    auto dest_utxos = index.GetUtxos(dest_sh);
    BOOST_REQUIRE_EQUAL(dest_utxos.size(), 1U);
    BOOST_CHECK(dest_utxos[0].outpoint.hash == spend_tx.GetHash());

    BlockValidationState state;
    CBlockIndex* tip_before_disconnect{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip_before_disconnect);
    BOOST_REQUIRE(tip_before_disconnect->GetBlockHash() == spend_block.GetHash());
    m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip_before_disconnect);
    BOOST_REQUIRE(state.IsValid());

    CreateAndProcessBlock({}, coinbase_spk);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(index.BlockUntilSyncedToCurrentChain());

    BOOST_CHECK(index.GetHistory(dest_sh).empty());
    BOOST_CHECK(index.GetUtxos(dest_sh).empty());
    BOOST_CHECK_EQUAL(index.GetBalance(dest_sh), 0);

    bool restored_outpoint{false};
    for (const auto& utxo : index.GetUtxos(coinbase_sh)) {
        if (utxo.outpoint.hash == m_coinbase_txns[0]->GetHash() && utxo.outpoint.n == 0) {
            restored_outpoint = true;
            BOOST_CHECK_EQUAL(utxo.value, m_coinbase_txns[0]->GetValueOut());
            break;
        }
    }
    BOOST_CHECK(restored_outpoint);

    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    index.Stop();
}

BOOST_FIXTURE_TEST_CASE(scripthashindex_pinned_cache_updates, TestChain100Setup)
{
    ScriptHashIndex index(interfaces::MakeChain(m_node), 1 << 20, true);
    BOOST_REQUIRE(index.Init());

    const CScript coinbase_spk = m_coinbase_txns[0]->vout[0].scriptPubKey;

    for (int i = 0; i < 50; i++) {
        CreateAndProcessBlock({}, coinbase_spk);
    }

    CScript dest_spk = CScript() << OP_TRUE;
    const uint256 dest_sh = ComputeScriptHashIndexHash(dest_spk);
    CMutableTransaction spend_tx{CreateSpendTx(m_coinbase_txns[0], coinbase_spk, dest_spk, coinbaseKey)};
    CreateAndProcessBlock({spend_tx}, coinbase_spk);
    index.Sync();

    index.CacheScriptHash(dest_sh);
    BOOST_CHECK_EQUAL(index.GetBalance(dest_sh), m_coinbase_txns[0]->GetValueOut());
    BOOST_REQUIRE_EQUAL(index.GetHistory(dest_sh).size(), 1U);

    CreateAndProcessBlock({}, dest_spk);
    index.Sync();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const auto history{index.GetHistory(dest_sh)};
    BOOST_REQUIRE_EQUAL(history.size(), 2U);
    BOOST_CHECK(history[0].txid != history[1].txid);
    BOOST_CHECK(index.GetBalance(dest_sh) > m_coinbase_txns[0]->GetValueOut());

    index.UncacheScriptHash(dest_sh);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    index.Stop();
}

BOOST_FIXTURE_TEST_CASE(scripthashindex_disk_restart_reads, TestChain100Setup)
{
    const CScript coinbase_spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    const uint256 coinbase_sh = ComputeScriptHashIndexHash(coinbase_spk);
    const CScript dest_spk = CScript() << OP_TRUE;
    const uint256 dest_sh = ComputeScriptHashIndexHash(dest_spk);
    CMutableTransaction spend_tx;

    {
        ScriptHashIndex index(interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/true);
        BOOST_REQUIRE(index.Init());

        for (int i = 0; i < 50; ++i) {
            CreateAndProcessBlock({}, coinbase_spk);
        }

        spend_tx = CreateSpendTx(m_coinbase_txns[0], coinbase_spk, dest_spk, coinbaseKey);
        CreateAndProcessBlock({spend_tx}, coinbase_spk);
        index.Sync();
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        index.Stop();
    }

    ScriptHashIndex reloaded(interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/false);
    BOOST_REQUIRE(reloaded.Init());
    BOOST_CHECK(reloaded.BlockUntilSyncedToCurrentChain());

    const auto dest_history = reloaded.GetHistory(dest_sh);
    BOOST_REQUIRE_EQUAL(dest_history.size(), 1U);
    BOOST_CHECK(dest_history[0].txid == spend_tx.GetHash());

    const auto dest_utxos = reloaded.GetUtxos(dest_sh);
    BOOST_REQUIRE_EQUAL(dest_utxos.size(), 1U);
    BOOST_CHECK(dest_utxos[0].outpoint.hash == spend_tx.GetHash());
    BOOST_CHECK_EQUAL(dest_utxos[0].outpoint.n, 0U);
    BOOST_CHECK_EQUAL(dest_utxos[0].value, m_coinbase_txns[0]->GetValueOut());

    BOOST_CHECK_EQUAL(reloaded.GetBalance(dest_sh), m_coinbase_txns[0]->GetValueOut());

    bool restored_outpoint{false};
    for (const auto& utxo : reloaded.GetUtxos(coinbase_sh)) {
        if (utxo.outpoint.hash == m_coinbase_txns[0]->GetHash() && utxo.outpoint.n == 0) {
            restored_outpoint = true;
            break;
        }
    }
    BOOST_CHECK(!restored_outpoint);

    reloaded.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
