package com.mknotes.app.adapter;

import android.content.Context;
import android.graphics.Paint;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ImageView;

import com.mknotes.app.R;
import com.mknotes.app.checklist.ChecklistManager;
import com.mknotes.app.model.ListItem;
import com.mknotes.app.util.HighlightText;

import java.util.List;

public class ChecklistAdapter extends BaseAdapter {

    private Context context;
    private ChecklistManager manager;
    private LayoutInflater inflater;
    private String highlightQuery;
    private int highlightColor;
    private int highlightTextColor;
    private int checkedTextColor;
    private int normalTextColor;
    private int childIndentPx;
    private ChecklistAdapterListener adapterListener;
    private int focusRequestPosition;
    private boolean suppressTextWatcher;

    public interface ChecklistAdapterListener {
        void onDragStartRequested(int position, View itemView);

        void onItemFocused(int position);
    }

    public ChecklistAdapter(Context context, ChecklistManager manager) {
        this.context = context;
        this.manager = manager;
        this.inflater = LayoutInflater.from(context);
        this.highlightQuery = null;
        this.highlightColor = context.getResources().getColor(R.color.checklist_highlight);
        this.highlightTextColor = context.getResources().getColor(R.color.checklist_highlight_text);
        this.checkedTextColor = context.getResources().getColor(R.color.checklist_checked_text);
        this.normalTextColor = context.getResources().getColor(R.color.text_primary);
        float density = context.getResources().getDisplayMetrics().density;
        this.childIndentPx = (int) (32 * density);
        this.focusRequestPosition = -1;
        this.suppressTextWatcher = false;
    }

    public void setAdapterListener(ChecklistAdapterListener listener) {
        this.adapterListener = listener;
    }

    public void setHighlightQuery(String query) {
        this.highlightQuery = query;
    }

    public void requestFocusAt(int position) {
        this.focusRequestPosition = position;
        notifyDataSetChanged();
    }

    public int getCount() {
        return manager.getItemCount();
    }

    public Object getItem(int position) {
        return manager.getItem(position);
    }

    public long getItemId(int position) {
        ListItem item = manager.getItem(position);
        return item != null ? item.getId() : position;
    }

    public boolean hasStableIds() {
        return true;
    }

    public View getView(final int position, View convertView, ViewGroup parent) {
        final ViewHolder holder;
        final View rowView;

        if (convertView == null) {
            rowView = inflater.inflate(R.layout.item_checklist, parent, false);
            holder = new ViewHolder();
            holder.dragHandle = (ImageView) rowView.findViewById(R.id.iv_drag_handle);
            holder.checkBox = (CheckBox) rowView.findViewById(R.id.cb_item);
            holder.editText = (EditText) rowView.findViewById(R.id.et_item_body);
            holder.deleteBtn = (ImageView) rowView.findViewById(R.id.iv_delete_item);
            rowView.setTag(holder);
        } else {
            rowView = convertView;
            holder = (ViewHolder) rowView.getTag();
            // Remove old text watcher
            if (holder.currentWatcher != null) {
                holder.editText.removeTextChangedListener(holder.currentWatcher);
                holder.currentWatcher = null;
            }
        }

        final ListItem item = manager.getItem(position);
        if (item == null) return rowView;

        final int pos = position;

        // Indentation for child items
        final int leftPad = item.isChild() ? childIndentPx : 0;
        rowView.setPadding(leftPad, rowView.getPaddingTop(),
                rowView.getPaddingRight(), rowView.getPaddingBottom());

        // Checkbox state
        holder.checkBox.setOnCheckedChangeListener(null);
        holder.checkBox.setChecked(item.isChecked());
        holder.checkBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                manager.toggleChecked(pos);
            }
        });

        // Text content with highlight support
        suppressTextWatcher = true;
        if (highlightQuery != null && highlightQuery.length() > 0) {
            CharSequence highlighted = HighlightText.highlight(
                    item.getBody(), highlightQuery, highlightColor, highlightTextColor);
            holder.editText.setText(highlighted);
        } else {
            holder.editText.setText(item.getBody());
        }
        suppressTextWatcher = false;

        // Strikethrough and color for checked items
        if (item.isChecked()) {
            holder.editText.setPaintFlags(holder.editText.getPaintFlags() | Paint.STRIKE_THRU_TEXT_FLAG);
            holder.editText.setTextColor(checkedTextColor);
        } else {
            holder.editText.setPaintFlags(holder.editText.getPaintFlags() & (~Paint.STRIKE_THRU_TEXT_FLAG));
            holder.editText.setTextColor(normalTextColor);
        }

        // Text watcher for edits
        TextWatcher watcher = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (!suppressTextWatcher) {
                    manager.setItemText(pos, s.toString());
                }
            }
        };
        holder.editText.addTextChangedListener(watcher);
        holder.currentWatcher = watcher;

        // Enter key handling - add new item after current
        holder.editText.setOnKeyListener(new View.OnKeyListener() {
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if (keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_DOWN) {
                    String currentText = holder.editText.getText().toString();
                    int cursorPos = holder.editText.getSelectionStart();

                    if (cursorPos >= 0 && cursorPos < currentText.length()) {
                        // Split text at cursor
                        String before = currentText.substring(0, cursorPos);
                        String after = currentText.substring(cursorPos);
                        manager.setItemText(pos, before);
                        manager.addItemAt(pos + 1, after);
                    } else {
                        manager.addItemAfter(pos);
                    }
                    return true;
                }
                if (keyCode == KeyEvent.KEYCODE_DEL && event.getAction() == KeyEvent.ACTION_DOWN) {
                    if (holder.editText.getSelectionStart() == 0 && pos > 0) {
                        String currentBody = item.getBody();
                        if (currentBody.length() == 0) {
                            manager.deleteItem(pos);
                            return true;
                        }
                    }
                }
                return false;
            }
        });

        // Focus tracking
        holder.editText.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            public void onFocusChange(View v, boolean hasFocus) {
                if (hasFocus) {
                    holder.deleteBtn.setVisibility(View.VISIBLE);
                    if (adapterListener != null) {
                        adapterListener.onItemFocused(pos);
                    }
                } else {
                    holder.deleteBtn.setVisibility(View.GONE);
                }
            }
        });

        // Delete button
        holder.deleteBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                manager.deleteItem(pos);
            }
        });

        // Drag handle touch listener
        holder.dragHandle.setOnTouchListener(new View.OnTouchListener() {
            public boolean onTouch(View v, MotionEvent event) {
                if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
                    if (adapterListener != null) {
                        adapterListener.onDragStartRequested(pos, rowView);
                    }
                }
                return false;
            }
        });

        // Long press on whole item to toggle indent
        rowView.setOnLongClickListener(new View.OnLongClickListener() {
            public boolean onLongClick(View v) {
                if (manager.canIndent(pos)) {
                    manager.toggleIndent(pos);
                    notifyDataSetChanged();
                    return true;
                }
                return false;
            }
        });

        // Handle focus request
        if (focusRequestPosition == position) {
            holder.editText.requestFocus();
            holder.editText.setSelection(holder.editText.getText().length());
            focusRequestPosition = -1;
        }

        return rowView;
    }

    static class ViewHolder {
        ImageView dragHandle;
        CheckBox checkBox;
        EditText editText;
        ImageView deleteBtn;
        TextWatcher currentWatcher;
    }
}
