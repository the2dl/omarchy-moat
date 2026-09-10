import QtQuick
import QtTest
import ".."

// MoatKeyed.qml keeps one item per KEY across changes of its list. This suite
// checks the property the panel depends on and a Repeater does not have: a
// row whose object did not change is the SAME item afterwards, untouched, and
// only the rows that appeared, vanished, moved or changed value cost anything.
//
// It runs under a bare qmltestrunner because MoatKeyed imports only QtQuick,
// like MoatScroll -- keep it that way.
TestCase {
  id: suite
  name: "MoatKeyed"

  Component {
    id: rowDelegate
    Item {
      property var value: null
      property int valueChanges: 0
      property int creations: 0
      width: 10
      height: 10
      onValueChanged: valueChanges++
      Component.onCompleted: creations++
    }
  }

  Component {
    id: keyed
    MoatKeyed {
      delegate: rowDelegate
    }
  }

  // Created, THEN given its list, the way the view's binding gives it one: a
  // JS array assigned from JS stays a JS array, and identity of its elements
  // is what this component is about. (A list handed to createObject as a
  // creation property is copied into a sequence, and every read of an element
  // is a new wrapper.)
  function make(items) {
    var column = keyed.createObject(suite)
    verify(column !== null, "MoatKeyed must instantiate")
    column.items = items
    return column
  }

  function keysOf(column) {
    var out = []
    for (var i = 0; i < column.children.length; i++) out.push(column.children[i].value.key)
    return out
  }

  function test_one_item_per_key_in_order() {
    var a = { key: "a" }, b = { key: "b" }
    var column = make([a, b])
    compare(column.children.length, 2)
    compare(keysOf(column), ["a", "b"])
    verify(column.itemFor("a").value === a)
    verify(column.itemFor("b").value === b)
    compare(column.itemFor("zzz"), null)
    column.destroy()
  }

  function test_a_new_array_of_the_same_objects_touches_nothing() {
    var a = { key: "a" }, b = { key: "b" }
    var column = make([a, b])
    var itemA = column.itemFor("a"), itemB = column.itemFor("b")
    compare(itemA.valueChanges, 1, "the creation assignment")

    // What every poll does: a NEW array, same rows.
    column.items = [a, b]
    verify(column.itemFor("a") === itemA, "the item for a kept key is the same item")
    verify(column.itemFor("b") === itemB)
    compare(itemA.valueChanges, 1, "a value that is the same object is not re-assigned")
    compare(itemB.valueChanges, 1)
    compare(itemA.creations, 1, "and nothing was created again")
    compare(column.children.length, 2)
    column.destroy()
  }

  function test_a_changed_value_reaches_the_kept_item() {
    var a = { key: "a", n: 1 }
    var column = make([a])
    var item = column.itemFor("a")
    var a2 = { key: "a", n: 2 }
    column.items = [a2]
    verify(column.itemFor("a") === item, "same key, same item")
    verify(item.value === a2, "with the new value")
    compare(item.valueChanges, 2)
    column.destroy()
  }

  function test_a_vanished_key_is_destroyed_and_a_new_one_created() {
    var a = { key: "a" }, b = { key: "b" }, c = { key: "c" }
    var column = make([a, b])
    var itemB = column.itemFor("b")
    column.items = [b, c]
    compare(column.itemFor("a"), null, "a is gone")
    verify(column.itemFor("b") === itemB, "b survived")
    verify(column.itemFor("c") !== null, "c was made")
    compare(keysOf(column), ["b", "c"])
    column.destroy()
  }

  function test_a_reorder_moves_items_rather_than_remaking_them() {
    var a = { key: "a" }, b = { key: "b" }, c = { key: "c" }, d = { key: "d" }
    var column = make([a, b, c, d])
    var items = [column.itemFor("a"), column.itemFor("b"), column.itemFor("c"), column.itemFor("d")]

    // The newest incident moving to the top is the common case.
    column.items = [d, a, b, c]
    compare(keysOf(column), ["d", "a", "b", "c"])
    verify(column.itemFor("d") === items[3])
    verify(column.itemFor("a") === items[0])
    for (var i = 0; i < 4; i++) compare(items[i].creations, 1, "no row was recreated")

    // And back.
    column.items = [a, b, c, d]
    compare(keysOf(column), ["a", "b", "c", "d"])
    // A swap in the middle.
    column.items = [a, c, b, d]
    compare(keysOf(column), ["a", "c", "b", "d"])
    verify(column.itemFor("b") === items[1])
    column.destroy()
  }

  function test_a_duplicate_key_is_one_row() {
    var a = { key: "a" }, a2 = { key: "a" }
    var column = make([a, a2])
    compare(column.children.length, 1)
    verify(column.itemFor("a").value === a, "the first wins")
    column.destroy()
  }

  function test_keyOf_can_be_replaced() {
    var column = keyed.createObject(suite)
    column.keyOf = function(item) { return String(item.id) }
    column.items = [{ id: 7 }, { id: 8 }]
    verify(column.itemFor("7") !== null)
    verify(column.itemFor("8") !== null)
    compare(column.children.length, 2)
    column.destroy()
  }

  function test_a_non_array_is_an_empty_list() {
    var column = make([{ key: "a" }])
    column.items = null
    compare(column.children.length, 0)
    column.items = undefined
    compare(column.children.length, 0)
    column.destroy()
  }
}
