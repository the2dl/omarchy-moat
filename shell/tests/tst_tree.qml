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

    function makeFull(props) {
        return createTemporaryObject(treeComponent, suite, props);
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
    /// The other children an ancestor started are context, and they are
    /// per-node: opening one must not open the rest, or a deep tree becomes a
    /// wall the moment you ask one question.
    /// The daemon caps `others` at twenty; `others_total` is the real number.
    /// A chip reading "20 other children" under a build that started 554 is a
    /// quieter lie than showing nothing, on the row whose entire job is
    /// answering "what else was that shell doing".
    function test_a_capped_sibling_list_still_reports_the_real_count() {
        var t = makeFull({
            "ancestry": [{
                "pid": 2,
                "exe": "/bin/sh",
                "others_total": 554,
                "others": [
                    { "pid": 20, "exe": "/usr/bin/rustc", "state": "exited" },
                    { "pid": 21, "exe": "/usr/bin/rustc", "state": "exited" }
                ]
            }],
            "process": { "pid": 3, "exe": "/usr/bin/curl" }
        })
        compare(t.otherTotalOf(t.nodes[0]), 554)
        compare(t.othersOf(t.nodes[0]).length, 2)

        // An uncapped list (no others_total, or one that is not larger) still
        // reports what is there -- an older daemon sends no such field.
        var plain = makeFull({
            "ancestry": [{
                "pid": 2, "exe": "/bin/sh",
                "others": [{ "pid": 20, "exe": "/usr/bin/rustc", "state": "exited" }]
            }],
            "process": { "pid": 3, "exe": "/usr/bin/curl" }
        })
        compare(plain.otherTotalOf(plain.nodes[0]), 1)
    }

    function test_other_children_reveal_one_node_at_a_time() {
        var t = makeFull({
            "ancestry": [{
                "pid": 2,
                "exe": "/bin/sh",
                "others": [{
                    "pid": 20,
                    "exe": "/usr/bin/rustc",
                    "state": "exited"
                }]
            }, {
                "pid": 1,
                "exe": "/usr/bin/systemd",
                "others": [{
                    "pid": 10,
                    "exe": "/usr/bin/sshd",
                    "state": "running"
                }]
            }],
            "process": {
                "pid": 3,
                "exe": "/usr/bin/cargo"
            }
        });
        compare(t.nodes.length, 3);
        compare(t.othersOf(t.nodes[0]).length, 1, "systemd's other child");
        compare(t.othersOf(t.nodes[1]).length, 1, "the shell's other child");
        compare(t.othersOf(t.nodes[2]).length, 0, "the flagged leaf started nothing");
        // Nothing revealed until asked.
        compare(t.revealed[0] === true, false);
        compare(t.revealed[1] === true, false);
    }

    /// The flagged process is the leaf and is selected when the card opens.
    /// Previously you counted rows to find which one the alert was about.
    function test_the_flagged_process_is_the_leaf_and_starts_selected() {
        var t = makeFull({
            "ancestry": [{
                "pid": 2,
                "exe": "/bin/sh"
            }],
            "process": {
                "pid": 3,
                "exe": "/usr/bin/cat"
            }
        });
        compare(t.selected, t.nodes.length - 1);
        compare(t.nodes[t.selected].pid, 3);
    }

    /// The header says how long the chain took, and says nothing rather than
    /// inventing a duration when the record has no start time -- records
    /// written before the daemon carried it do not, and a made-up number here
    /// reads as evidence.
    function test_the_duration_is_omitted_when_it_cannot_be_computed() {
        var withTime = makeFull({
            "ancestry": [{
                "pid": 1,
                "exe": "/a",
                "start_time": "2026-09-11T00:39:00.000Z"
            }],
            "process": {
                "pid": 2,
                "exe": "/b"
            },
            "alertTs": "2026-09-11T00:39:50.000Z"
        });
        compare(withTime.headline, "2 processes  ·  50s from the first to the read");

        var without = makeFull({
            "ancestry": [{
                "pid": 1,
                "exe": "/a"
            }],
            "process": {
                "pid": 2,
                "exe": "/b"
            },
            "alertTs": "2026-09-11T00:39:50.000Z"
        });
        compare(without.headline, "2 processes", "no start time, no claim");
    }

    /// An older record has pid and exe and nothing else. It must still draw.
    function test_a_record_without_the_detail_still_draws() {
        var t = makeFull({
            "ancestry": [{
                "pid": 1,
                "exe": "/usr/lib/systemd/systemd"
            }],
            "process": {
                "pid": 2,
                "exe": "/usr/bin/cat"
            }
        });
        compare(t.nodes.length, 2);
        compare(t.summary, "systemd  →  cat");
        compare(t.othersOf(t.nodes[0]).length, 0, "absent is empty, never undefined");
        compare(t.eventsFor(2).length, 0);
    }

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
