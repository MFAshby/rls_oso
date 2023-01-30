create policy "oso_update" on "{{ table_name }}" 
    for update
using (
    -- TODO how to correctly authorize an update? At least I'm going to authorize I can select the row, before updating it.
    oso_is_allowed(current_setting('virt.vuser', true), 'select', ({{ table_cols|join(",") }})::{{ table_name }})
)
with check (
    oso_is_allowed(current_setting('virt.vuser', true), 'update', ({{ table_cols|join(",") }})::{{ table_name }})
)
