package com.mknotes.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Category;
import com.mknotes.app.util.NoteColorUtil;
import com.mknotes.app.util.SessionManager;

import java.util.ArrayList;
import java.util.List;

public class CategoryActivity extends Activity {

    private ListView listCategories;
    private NotesRepository repository;
    private CategoryAdapter adapter;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_category);

        repository = NotesRepository.getInstance(this);

        initViews();
        loadCategories();
    }

    private void initViews() {
        listCategories = (ListView) findViewById(R.id.list_categories);

        ImageButton btnBack = (ImageButton) findViewById(R.id.btn_cat_back);
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finish();
            }
        });

        ImageButton btnAdd = (ImageButton) findViewById(R.id.btn_add_category);
        btnAdd.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showAddCategoryDialog();
            }
        });

        adapter = new CategoryAdapter();
        listCategories.setAdapter(adapter);
    }

    private void loadCategories() {
        List categories = repository.getAllCategories();
        adapter.setCategories(categories);
    }

    private void showAddCategoryDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.add_category);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 24, 48, 8);

        final EditText input = new EditText(this);
        input.setHint(R.string.category_name_hint);
        layout.addView(input);

        final int[] selectedColor = {0};
        final LinearLayout colorRow = new LinearLayout(this);
        colorRow.setOrientation(LinearLayout.HORIZONTAL);
        colorRow.setGravity(Gravity.CENTER);
        colorRow.setPadding(0, 16, 0, 0);

        int[] colors = NoteColorUtil.getAllPresetColors();
        for (int i = 1; i < colors.length; i++) {
            final int colorIndex = i;
            View colorView = new View(this);
            int size = 36;
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(size, size);
            params.setMargins(6, 6, 6, 6);
            colorView.setLayoutParams(params);

            GradientDrawable shape = new GradientDrawable();
            shape.setShape(GradientDrawable.OVAL);
            shape.setColor(colors[i]);
            colorView.setBackground(shape);

            colorView.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    selectedColor[0] = colorIndex;
                    for (int j = 0; j < colorRow.getChildCount(); j++) {
                        View child = colorRow.getChildAt(j);
                        GradientDrawable bg = new GradientDrawable();
                        bg.setShape(GradientDrawable.OVAL);
                        bg.setColor(NoteColorUtil.getPresetColor(j + 1));
                        if (j == colorIndex - 1) {
                            bg.setStroke(3, Color.BLACK);
                        }
                        child.setBackground(bg);
                    }
                }
            });

            colorRow.addView(colorView);
        }
        layout.addView(colorRow);

        builder.setView(layout);
        builder.setPositiveButton(R.string.add, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                String name = input.getText().toString().trim();
                if (name.length() > 0) {
                    Category category = new Category(name, selectedColor[0]);
                    repository.insertCategory(category);
                    loadCategories();
                } else {
                    Toast.makeText(CategoryActivity.this, R.string.enter_name, Toast.LENGTH_SHORT).show();
                }
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private void confirmDeleteCategory(final Category category) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.delete_category_title);
        builder.setMessage(getString(R.string.delete_category_message, category.getName()));
        builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                repository.deleteCategory(category.getId());
                loadCategories();
                Toast.makeText(CategoryActivity.this, R.string.category_deleted, Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private class CategoryAdapter extends BaseAdapter {

        private List categories = new ArrayList();

        public void setCategories(List categories) {
            this.categories = categories;
            notifyDataSetChanged();
        }

        public int getCount() {
            return categories.size();
        }

        public Object getItem(int position) {
            return categories.get(position);
        }

        public long getItemId(int position) {
            return ((Category) categories.get(position)).getId();
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(CategoryActivity.this)
                        .inflate(R.layout.item_category, parent, false);
            }

            final Category category = (Category) categories.get(position);

            View colorDot = convertView.findViewById(R.id.category_color_dot);
            TextView tvName = (TextView) convertView.findViewById(R.id.tv_category_name);
            TextView tvCount = (TextView) convertView.findViewById(R.id.tv_category_count);
            ImageButton btnDelete = (ImageButton) convertView.findViewById(R.id.btn_delete_category);

            tvName.setText(category.getName());

            int count = repository.getNotesCountForCategory(category.getId());
            tvCount.setText(String.valueOf(count));

            GradientDrawable dotBg = new GradientDrawable();
            dotBg.setShape(GradientDrawable.OVAL);
            int catColor = category.getColor();
            if (catColor > 0) {
                dotBg.setColor(NoteColorUtil.getPresetColor(catColor));
            } else {
                dotBg.setColor(Color.GRAY);
            }
            colorDot.setBackground(dotBg);

            btnDelete.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    confirmDeleteCategory(category);
                }
            });

            return convertView;
        }
    }
}
