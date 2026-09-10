import QtQuick

// A Column of one item per KEY, kept across changes of the list.
//
// A Repeater over a JS array is a Repeater over a value: assign it a new array
// and it destroys every delegate and creates every one again, whatever the
// arrays have in common. The panel's lists are rebuilt on every poll -- one
// poll a second under a burst -- so every row on the page was created about
// once a second for a list in which one row had changed. This keeps the item
// made for a key for as long as the key is listed, gives it the new value only
// when the value is a different object, and moves items rather than remaking
// them when the order changes. Cost is proportional to what changed, which is
// the property a list rebuilt this often has to have.
//
// The delegate declares `property var value` and reads its row from it. It is
// created in the scope it was written in, so it can reach its view's `root`
// the way a Repeater delegate does; it gets no `index`, because an index is
// exactly the thing that changes when a row it is not about moves.
//
// Pure QtQuick on purpose, like MoatScroll: it imports nothing from
// Quickshell so tests/tst_keyed.qml can instantiate it under qmltestrunner.
Column {
    id: root

    /// The rows, in order. Each is a plain object; `keyOf` names it.
    property var items: []
    /// The key of one row. Defaults to `item.key`, which is what an incident
    /// and a day group both carry.
    property var keyOf: function(item) {
        return item && item.key !== undefined ? String(item.key) : "";
    }
    /// One item per row, with `property var value`.
    property Component delegate: null
    /// key -> live item. Read by `itemFor`; written only by `sync`.
    property var _live: ({
    })

    /// The live item for a key, or null. For tests and for callers that need
    /// to scroll a row into view.
    function itemFor(key) {
        var item = root._live[String(key)];
        return item ? item : null;
    }

    /// Make the children match `items`: create for a new key, update a kept
    /// key whose value is a different object, destroy a key no longer listed,
    /// and reorder only from the first row that is out of place.
    function sync() {
        if (!root.delegate)
            return ;

        // Array-like, not Array: a list handed over as a creation property
        // arrives as a sequence reference, not a JS Array, and a binding to a
        // JS array arrives as one. Both have a length and an indexer.
        var list = root.items && typeof root.items.length === "number" ? root.items : [];
        var live = root._live;
        var next = ({
        });
        var ordered = [];
        for (var i = 0; i < list.length; i++) {
            var value = list[i];
            var key = String(root.keyOf(value));
            // A duplicate key is one row, the first.
            if (next[key])
                continue;

            var item = live[key];
            if (!item) {
                // Created bare and given its value from JS, never as a
                // creation property: a creation property is copied into a
                // QVariantMap and every read of it is a new wrapper, so the
                // identity test below would fail on every sync -- and the
                // item's bindings would re-evaluate on every poll, for a row
                // that did not change.
                item = root.delegate.createObject(root);
                if (!item)
                    continue;

                item.value = value;
            } else if (item.value !== value) {
                item.value = value;
            }
            next[key] = item;
            ordered.push(item);
        }
        for (var gone in live) {
            if (!next[gone]) {
                // Out of the Column now, not when the deferred destroy lands,
                // so the order check below sees only the rows that stay.
                live[gone].parent = null;
                live[gone].destroy();
            }
        }
        root._live = next;
        // A Column lays its children out in child order, and the only way to
        // move a child is to re-parent it, which appends. So from the first
        // row that is out of place, every row after it is appended in order.
        var from = -1;
        for (var j = 0; j < ordered.length; j++) {
            if (root.children[j] !== ordered[j]) {
                from = j;
                break;
            }
        }
        if (from >= 0) {
            for (var m = from; m < ordered.length; m++) {
                ordered[m].parent = null;
                ordered[m].parent = root;
            }
        }
    }

    onItemsChanged: root.sync()
    onDelegateChanged: root.sync()
    Component.onCompleted: root.sync()
}
