package xyz.cirno.avbsign;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;

import com.google.android.material.appbar.MaterialToolbar;

public class BackupActivity extends BaseAvbActivity {
    static final String EXTRA_MANAGE = "manage";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_bootloader_settings);
        applySystemBarInsets(findViewById(R.id.settings_root));
        MaterialToolbar toolbar = findViewById(R.id.settings_toolbar);
        setSupportActionBar(toolbar);
        var bar = getSupportActionBar();
        if (bar != null) {
            bar.setDisplayHomeAsUpEnabled(true);
        }
        if (state == null) {
            BackupListFragment fragment = getIntent().getBooleanExtra(EXTRA_MANAGE, false)
                    ? new ManageBackupsFragment() : new BackupConfigFragment();
            getSupportFragmentManager().beginTransaction()
                    .replace(R.id.settings_content, fragment).commitNow();
        }
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                var fragment = fragment();
                if (fragment != null && fragment.isEditing()) {
                    fragment.exitEditMode();
                } else {
                    finish();
                }
            }
        });
        onShizukuAvailable();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.bootloader_settings, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        var action = menu.findItem(R.id.action_edit);
        var fragment = fragment();
        if (action != null && fragment != null) {
            action.setTitle(fragment.isEditing() ? "删除" : "编辑");
            action.setEnabled(fragment.canEditAction());
        }
        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            getOnBackPressedDispatcher().onBackPressed();
            return true;
        }
        if (item.getItemId() == R.id.action_edit) {
            var fragment = fragment();
            if (fragment != null) {
                if (fragment.isEditing()) fragment.confirmDelete();
                else fragment.enterEditMode();
            }
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onServiceReady() {
        var fragment = fragment();
        if (fragment != null) fragment.refresh();
    }

    @Override
    protected void onShizukuStateChanged() {
        var fragment = fragment();
        if (fragment != null && service == null) fragment.serviceDisconnected();
    }

    private BackupListFragment fragment() {
        var value = getSupportFragmentManager().findFragmentById(R.id.settings_content);
        return value instanceof BackupListFragment ? (BackupListFragment) value : null;
    }
}
