import QtQuick
import QtTest
import ".."

TestCase {
    id: suite
    name: "ProcessTree"
    width: 400
    height: 400

    Component {
        id: treeComponent
        ProcessTree {
            width: 400
        }
    }

    function make(ancestry, process) {
        return createTemporaryObject(treeComponent, suite, {
            "ancestry": ancestry,
            "process": process
        });
    }

    /// The record stores ancestry nearest-parent-first because that is the
    /// order the kernel walks it. A person reads a causal chain the other way,
    /// and the alerting process -- which the record keeps outside the list --
    /// belongs at the end of it, not missing from it.
    function test_the_chain_reads_oldest_first_with_the_alerting_process_last() {
        var t = make([{
            "pid": 2,
            "exe": "/bin/sh"
        }, {
            "pid": 1,
            "exe": "/usr/lib/systemd/systemd"
        }], {
            "pid": 3,
            "exe": "/usr/bin/pg_isready"
        });
        compare(t.nodes.length, 3);
        compare(t.nodes[0].exe, "/usr/lib/systemd/systemd");
        compare(t.nodes[1].exe, "/bin/sh");
        compare(t.nodes[2].exe, "/usr/bin/pg_isready", "the alert's own process is the leaf");
        compare(t.summary, "systemd  →  sh  →  pg_isready");
    }

    /// A short chain opens itself: three or four processes is the whole answer,
    /// and hiding it behind a click meant nobody found it.
    function test_a_short_chain_opens_itself() {
        var t = make([{
            "pid": 1,
            "exe": "/a"
        }], {
            "pid": 2,
            "exe": "/b"
        });
        compare(t.nodes.length, 2);
        compare(t.open, true, "two processes is worth reading straight away");
    }

    /// A long one does not. Container and package-manager chains are where
    /// these get deep, and History builds many cards at once.
    function test_a_long_chain_stays_folded() {
        var deep = [];
        for (var i = 0; i < 8; i++) {
            deep.push({
                "pid": i,
                "exe": "/p" + i
            });
        }
        var t = make(deep, {
            "pid": 99,
            "exe": "/leaf"
        });
        compare(t.nodes.length, 9);
        compare(t.open, false, "past autoOpenMax it waits to be asked");
    }

    /// Closed builds nothing: that is the whole reason the rows sit behind a
    /// Loader rather than being built and hidden.
    function test_a_closed_tree_builds_no_rows() {
        var deep = [];
        for (var i = 0; i < 8; i++) {
            deep.push({
                "pid": i,
                "exe": "/p" + i
            });
        }
        var t = make(deep, {
            "pid": 99,
            "exe": "/b"
        });
        compare(t.open, false, "long enough to start folded");
        var loader = null;
        for (var i = 0; i < t.children.length; i++) {
            if (t.children[i].hasOwnProperty("sourceComponent"))
                loader = t.children[i];
        }
        verify(loader !== null, "the rows live behind a Loader");
        compare(loader.active, false, "nothing is built until it is opened");
        verify(loader.item === null);

        t.open = true;
        compare(loader.active, true);
        verify(loader.item !== null, "opening builds the rows");
    }

    /// An alert whose record carries no ancestry must not leave an empty
    /// disclosure arrow on the card with nothing behind it.
    function test_nothing_to_show_is_not_shown() {
        var t = make([], null);
        compare(t.nodes.length, 0);
        // NOT `t.visible`: that is effective visibility, and nothing parented
        // under a headless TestCase is ever visible, so the assertion passed
        // for every input including the ones it was meant to catch. The
        // binding's own input is the honest thing to check.
        compare(t.nodes.length > 0, false, "an empty chain draws no disclosure arrow");
    }

    /// A process with no ancestry is still worth drawing: it is one node, and
    /// "this ran with no parent we recorded" is a fact about the alert.
    function test_a_lone_process_is_still_a_tree_of_one() {
        var t = make([], {
            "pid": 9,
            "exe": "/usr/bin/cat"
        });
        compare(t.nodes.length, 1);
        compare(t.summary, "cat");
        compare(t.nodes.length > 0, true);
    }

    /// Records from an older daemon, and containers, both produce entries with
    /// pieces missing. A tree that renders "undefined" is worse than one that
    /// says it does not know.
    function test_a_missing_pid_or_path_renders_as_unknown_not_undefined() {
        var t = make([{
            "exe": "/bin/sh"
        }, {
            "pid": 4
        }], {
            "pid": 5,
            "exe": "/x"
        });
        compare(t.nodes.length, 3);
        compare(t.summary, "?  →  sh  →  x", "a nameless ancestor is '?', never 'undefined'");
        t.open = true;
        verify(String(t.summary).indexOf("undefined") < 0);
    }
}
