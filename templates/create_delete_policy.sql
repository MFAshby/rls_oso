create policy "oso_delete" on "{{ table_name }}" 
    for delete
using (
    oso_is_allowed(current_setting('virt.vuser', true), 'delete', ({{ table_cols|join(",") }})::{{ table_name }})
)
