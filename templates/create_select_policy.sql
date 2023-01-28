create policy "oso_select" on "{{ table_name }}" 
    for select
using (
    oso_is_allowed(current_setting('virt.vuser', true), ({{ table_cols|join(",") }})::{{ table_name }}, 'select')
)
