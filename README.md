# VIEWPAY website starter

## Included
- `index.html`: responsive advertiser portal with email/password authentication, dashboard, view screenshot submission, activation-code redemption, withdrawal requests, support chat, and basic admin screens.
- `supabase-setup.sql`: database schema, RLS policies, private evidence bucket, single-use activation codes, and admin review functions.

## Setup
1. Create a Supabase project.
2. Open SQL Editor and run `supabase-setup.sql`.
3. In Authentication > Providers, enable Email. Configure email confirmation and SMTP for production.
4. Create your first user through the website.
5. In SQL Editor, promote your account:
   `update public.profiles set role='admin' where id=(select id from auth.users where email='YOUR_ADMIN_EMAIL');`
6. Host `index.html` on HTTPS (Netlify, Cloudflare Pages, Vercel, or your own host).
7. Open the website and enter your Supabase Project URL and anon/public key.
8. Sign in as admin. Generate activation codes only after independently confirming the KSh 200 payment.

## Important production notes
- Never put the Supabase `service_role` key in browser code.
- Admin approval is required before screenshots can earn credit.
- The included view approval function records approved earnings in `pending_balance`. Admins must release verified pending earnings to `available_balance` using the `admin_release_pending` RPC before withdrawals can be requested.
- The first KSh 200 registration-fee refund is not automatically included by this starter. It must be separately accounted for and funded at the first payout. Do not promise or process it unless VIEWPAY has funds and a documented refund policy.
- Withdrawal requests reserve available balance. Admin approval marks a request paid; rejection restores the reserved amount.
- This is a starter implementation, not a complete audited financial system. Before launch, add audit logs, admin user management, rate limits, email notifications, robust chat conversation controls, refund automation, and independent security review.
- Restrict admin access to trusted staff. Use Supabase Auth MFA for admins.
- Do not use screenshots alone as conclusive proof of views; cross-check submissions and prevent duplicate campaign evidence.
