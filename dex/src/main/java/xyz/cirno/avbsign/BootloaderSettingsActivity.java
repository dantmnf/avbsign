package xyz.cirno.avbsign;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.activity.OnBackPressedCallback;

import com.google.android.material.appbar.MaterialToolbar;

public class BootloaderSettingsActivity extends BaseAvbActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bootloader_settings);
        applySystemBarInsets(findViewById(R.id.settings_root));

        MaterialToolbar toolbar = findViewById(R.id.settings_toolbar);
        setSupportActionBar(toolbar);
        var actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
            actionBar.setTitle("替换 bootloader 设置");
        }

        if (savedInstanceState == null) {
            getSupportFragmentManager().beginTransaction()
                    .replace(R.id.settings_content, new BootloaderSettingsFragment())
                    .commitNow();
        }
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                var fragment = settingsFragment();
                if (fragment != null && fragment.isEditing()) {
                    if (fragment.isFileOperationInProgress()) {
                        toast("请等待文件操作完成");
                    } else {
                        fragment.exitEditMode();
                    }
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
        var fragment = settingsFragment();
        var action = menu.findItem(R.id.action_edit);
        if (fragment != null && action != null) {
            action.setTitle(fragment.isEditing() ? "删除" : "编辑");
            action.setEnabled(!fragment.isFileOperationInProgress()
                    && (!fragment.isEditing() || fragment.canDeleteSelection()));
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
            var fragment = settingsFragment();
            if (fragment != null) {
                if (fragment.isEditing()) {
                    fragment.confirmDeleteSelection();
                } else {
                    fragment.enterEditMode();
                }
            }
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onShizukuStateChanged() {
        var fragment = settingsFragment();
        if (fragment != null) {
            fragment.onServiceStateChanged();
        }
    }

    @Override
    protected void onServiceReady() {
        var fragment = settingsFragment();
        if (fragment != null) {
            fragment.refreshFiles();
        }
    }

    private BootloaderSettingsFragment settingsFragment() {
        var fragment = getSupportFragmentManager().findFragmentById(R.id.settings_content);
        return fragment instanceof BootloaderSettingsFragment
                ? (BootloaderSettingsFragment) fragment : null;
    }
}
