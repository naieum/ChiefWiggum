# Audit Supabase Configuration

Check Supabase configuration for security issues.

## Instructions

If this project uses Supabase, audit the configuration for security issues:

1. **Row Level Security (RLS)**:
   - Check `supabase/migrations/*.sql` for tables without RLS enabled
   - Look for `CREATE TABLE` without corresponding `ENABLE ROW LEVEL SECURITY`
   - Verify RLS policies exist for sensitive tables

2. **Environment Configuration**:
   - Check that Supabase keys are in .env (not hardcoded)
   - Verify .env is in .gitignore
   - Check for exposed service_role keys (should never be client-side)

3. **JWT Configuration**:
   - Look for custom JWT secrets
   - Check JWT expiry settings in supabase/config.toml

4. **Report format**:
   ```
   ## Supabase Security Audit

   ### RLS Status
   | Table | RLS Enabled | Policies |
   |-------|-------------|----------|
   | users | Yes | select, insert |
   | posts | NO | MISSING |

   ### Configuration Issues
   - [List any issues found]

   ### Recommendations
   - [Specific remediation steps]
   ```

If Supabase is not detected, report that and suggest checking manually if the user is using Supabase.
