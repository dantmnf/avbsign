package xyz.cirno.avbsign;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;

final class EditSelection {
    private boolean editing;
    private final LinkedHashSet<String> selected = new LinkedHashSet<>();

    boolean isEditing() {
        return editing;
    }

    void enter() {
        editing = true;
        selected.clear();
    }

    void exit() {
        editing = false;
        selected.clear();
    }

    void restore(boolean editing, Collection<String> names) {
        this.editing = editing;
        selected.clear();
        if (editing && names != null) {
            selected.addAll(names);
        }
    }

    void toggle(String name) {
        if (!editing) {
            throw new IllegalStateException("Selection requires edit mode");
        }
        if (!selected.remove(name)) {
            selected.add(name);
        }
    }

    boolean contains(String name) {
        return selected.contains(name);
    }

    boolean isEmpty() {
        return selected.isEmpty();
    }

    ArrayList<String> snapshot() {
        return new ArrayList<>(selected);
    }

    void removeAll(Collection<String> names) {
        selected.removeAll(names);
    }

    void retainAll(Collection<String> names) {
        selected.retainAll(names);
    }
}
