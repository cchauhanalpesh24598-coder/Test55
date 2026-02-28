package com.mknotes.app.adapter;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.mknotes.app.R;
import com.mknotes.app.model.Note;
import com.mknotes.app.util.DateUtils;
import com.mknotes.app.util.NoteColorUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NoteAdapter extends BaseAdapter {

    private Context context;
    private List notes;
    private LayoutInflater inflater;
    private boolean isGridMode = false;
    private Set selectedIds;

    public NoteAdapter(Context context) {
        this.context = context;
        this.notes = new ArrayList();
        this.inflater = LayoutInflater.from(context);
        this.selectedIds = new HashSet();
    }

    public void setNotes(List notes) {
        this.notes = notes;
        notifyDataSetChanged();
    }

    public void setGridMode(boolean gridMode) {
        this.isGridMode = gridMode;
        notifyDataSetChanged();
    }

    public boolean isGridMode() {
        return isGridMode;
    }

    public void setSelectedIds(Set ids) {
        this.selectedIds = ids;
    }

    public void clearSelection() {
        this.selectedIds.clear();
    }

    public int getCount() {
        return notes.size();
    }

    public Object getItem(int position) {
        return notes.get(position);
    }

    public long getItemId(int position) {
        return ((Note) notes.get(position)).getId();
    }

    public int getViewTypeCount() {
        return 2;
    }

    public int getItemViewType(int position) {
        return isGridMode ? 1 : 0;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder holder;
        int layoutRes = isGridMode ? R.layout.item_note_grid : R.layout.item_note;

        if (convertView == null) {
            convertView = inflater.inflate(layoutRes, parent, false);
            holder = new ViewHolder();
            holder.tvTitle = (TextView) convertView.findViewById(R.id.tv_note_title);
            holder.tvContent = (TextView) convertView.findViewById(R.id.tv_note_content);
            holder.tvDate = (TextView) convertView.findViewById(R.id.tv_note_date);
            holder.icFavorite = (ImageView) convertView.findViewById(R.id.ic_favorite);
            holder.icLocked = (ImageView) convertView.findViewById(R.id.ic_locked);
            holder.icHasImage = (ImageView) convertView.findViewById(R.id.ic_has_image);
            holder.tvCategory = (TextView) convertView.findViewById(R.id.tv_category);
            holder.colorIndicator = convertView.findViewById(R.id.color_indicator);
            convertView.setTag(holder);
        } else {
            holder = (ViewHolder) convertView.getTag();
        }

        Note note = (Note) notes.get(position);

        // Title
        if (note.getTitle() != null && note.getTitle().length() > 0) {
            holder.tvTitle.setText(note.getTitle());
            holder.tvTitle.setVisibility(View.VISIBLE);
        } else {
            holder.tvTitle.setVisibility(View.GONE);
        }

        // Content preview
        String preview = note.getPreview();
        if (preview != null && preview.length() > 0) {
            holder.tvContent.setText(preview);
            holder.tvContent.setVisibility(View.VISIBLE);
        } else {
            holder.tvContent.setVisibility(View.GONE);
        }

        // Date
        holder.tvDate.setText(DateUtils.formatNoteDate(note.getModifiedAt()));

        // Favorite icon
        holder.icFavorite.setVisibility(note.isFavorite() ? View.VISIBLE : View.GONE);

        // Lock icon
        holder.icLocked.setVisibility(note.isLocked() ? View.VISIBLE : View.GONE);

        // Image icon
        holder.icHasImage.setVisibility(note.hasImage() ? View.VISIBLE : View.GONE);

        // Color indicator - show for any non-default color
        int storedColor = note.getColor();
        if (storedColor != 0) {
            holder.colorIndicator.setBackgroundColor(NoteColorUtil.resolveColor(storedColor));
            holder.colorIndicator.setVisibility(View.VISIBLE);
        } else {
            holder.colorIndicator.setVisibility(View.GONE);
        }

        // Selection highlight
        boolean isSelected = selectedIds.contains(Long.valueOf(note.getId()));
        if (isSelected) {
            GradientDrawable selBg = new GradientDrawable();
            selBg.setShape(GradientDrawable.RECTANGLE);
            selBg.setCornerRadius(dpToPx(8));
            selBg.setColor(Color.parseColor("#2A4A9EFF"));
            selBg.setStroke(dpToPx(2), Color.parseColor("#4A9EFF"));
            convertView.setBackground(selBg);
        } else {
            convertView.setBackgroundResource(R.drawable.note_item_bg);
        }

        return convertView;
    }

    private int dpToPx(int dp) {
        float density = context.getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }

    static class ViewHolder {
        TextView tvTitle;
        TextView tvContent;
        TextView tvDate;
        ImageView icFavorite;
        ImageView icLocked;
        ImageView icHasImage;
        TextView tvCategory;
        View colorIndicator;
    }
}
