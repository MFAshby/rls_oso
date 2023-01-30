create policy "oso_insert" on "{{ table_name }}" 
    for insert
with check (
    oso_is_allowed(current_setting('virt.vuser', true), 'insert', ({{ table_cols|join(",") }})::{{ table_name }})
)
