"""Stable page selector tables and auth-state sets for the Camoufox flow.

Moved verbatim from ``free_camoufox_runtime`` so the runtime module keeps only
behaviour.  The runtime module re-exports every name below to preserve the
historical ``runtime.EMAIL_SELECTORS`` style access for tests and adapters.
"""

from __future__ import annotations


CHATGPT_LOGIN_URL = "https://chatgpt.com/auth/login"
EMAIL_SELECTORS = (
    "input#login-email", "input[type='email']", "input[name='email']",
    "input[name='username']", "input[autocomplete='username']",
    "input[autocomplete*='username']", "input[autocomplete*='email']",
    "input[inputmode='email']", "input[id*='email' i]",
)
OTP_SELECTORS = (
    "input[autocomplete='one-time-code']", "input[inputmode='numeric']",
    "input[type='tel']", "input[name*='code' i]", "input[id*='code' i]",
)
PASSWORD_SELECTORS = (
    "input[type='password']", "input[name='password']", "input[name*='password' i]",
    "input[autocomplete='new-password']",
)
LOGIN_PASSWORD_SELECTORS = (
    "input[autocomplete='current-password']", "input[type='password']",
    "input[name='password']", "input[name*='password' i]",
)
NAME_SELECTORS = (
    "input[name='name']", "input[name='full_name']", "input[autocomplete='name']",
    "input[id*='name' i]", "input[placeholder*='name' i]",
)
BIRTHDAY_SELECTORS = (
    "input[name='birthday']", "input[type='date']", "input[name='birthdate']",
    "input[name='birth_date']", "input[autocomplete='bday']",
    "input[id*='birth' i]", "input[placeholder*='birth' i]",
)
AGE_SELECTORS = (
    "input[name='age']", "input[type='number'][name*='age' i]",
    "input[placeholder*='age' i]", "input[id*='age' i]",
)
EMAIL_SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')", "button:has-text('Next')",
    "button:has-text('Sign up')", "button:has-text('sign up')",
    "button:has-text('创建账号')", "button:has-text('注册')",
)
PASSWORD_SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')",
    "button:has-text('Create account')", "button:has-text('create account')",
    "button:has-text('Sign up')", "button:has-text('创建账号')", "button:has-text('注册')",
)
PASSWORDLESS_SELECTORS = (
    "a[href*='passwordless']", "button:has-text('email code')",
    "button:has-text('Email code')", "button:has-text('Use email')",
    "a:has-text('Use email')", "button:has-text('邮箱验证码')",
    "button:has-text('verification code')", "a:has-text('verification code')",
)
LOGIN_PASSWORD_SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']",
    "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')",
    "button:has-text('Sign in')", "button:has-text('sign in')",
    "button:has-text('Log in')", "button:has-text('log in')",
    "button:has-text('登录')", "button:has-text('登入')",
)
RESEND_SELECTORS = (
    "button:has-text('Resend')", "button:has-text('resend')",
    "button:has-text('重新发送')", "button:has-text('重发')",
    "a[href*='resend' i]", "[role='button']:has-text('Resend')",
)
PROFILE_SUBMIT_SELECTORS = (
    "button[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('Sign up')",
    "button:has-text('Create account')", "button:has-text('完成')",
)
_POST_ENTRY_AUTH_STATES = frozenset({
    "otp", "otp_wait", "email_verification", "signup_password",
    "login_password", "login_totp", "profile", "oauth_callback", "home",
})

__all__ = [
    "CHATGPT_LOGIN_URL",
    "EMAIL_SELECTORS",
    "OTP_SELECTORS",
    "PASSWORD_SELECTORS",
    "LOGIN_PASSWORD_SELECTORS",
    "NAME_SELECTORS",
    "BIRTHDAY_SELECTORS",
    "AGE_SELECTORS",
    "EMAIL_SUBMIT_SELECTORS",
    "PASSWORD_SUBMIT_SELECTORS",
    "PASSWORDLESS_SELECTORS",
    "LOGIN_PASSWORD_SUBMIT_SELECTORS",
    "RESEND_SELECTORS",
    "PROFILE_SUBMIT_SELECTORS",
    "_POST_ENTRY_AUTH_STATES",
]
