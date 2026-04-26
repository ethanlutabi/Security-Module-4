"""HTML sanitizer for Gruyere, a web application with holes.

Copyright 2017 Google Inc. All rights reserved.

This code is licensed under the https://creativecommons.org/licenses/by-nd/3.0/us/
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
https://www.google.com/intl/en/policies/terms/
"""

__author__ = 'Bruce Leban'

# system modules
import re


def SanitizeHtml(s):
  """Makes html safe for embedding in a document.

  Filters the html to exclude all but a small subset of html by
  removing script tags/attributes.

  Args:
    s: some html to sanitize.

  Returns:
    The html with all unsafe html removed.
  """
  processed = ''
  while s:
    start = s.find('<')
    if start >= 0:
      end = s.find('>', start)
      if end >= 0:
        before = s[:start]
        tag = s[start:end+1]
        after = s[end+1:]
      else:
        before = s[:start]
        tag = s[start:]
        after = ''
    else:
      before = s
      tag = ''
      after = ''

    processed += before + _SanitizeTag(tag)
    s = after
  return processed


TAG_RE = re.compile(r'<(.*?)(\s|>)', re.IGNORECASE)  # matches the start of an html tag

# FIX (Stored XSS - Challenge 3):
# The original code used a BLACKLIST of disallowed attributes which is
# fundamentally flawed — it missed 'onmouseover' and was case-sensitive,
# meaning 'ONMOUSEOVER' bypassed it entirely.
#
# Fix 1: Switched to a WHITELIST of allowed attributes only — anything
#         not on this list is stripped, so new event handlers can never sneak through.
# Fix 2: All comparisons are now case-insensitive (.lower()) so attackers
#         cannot bypass the check using uppercase variants like ONMOUSEOVER.
# Fix 3: Malformed tags (those that don't match the expected structure) are
#         now blocked entirely rather than passed through unchanged.

def _SanitizeTag(t):
  """Sanitizes a single html tag.

  Uses a strict WHITELIST for both allowed tags and allowed attributes.
  All comparisons are case-insensitive to prevent case-based bypasses.

  Args:
    t: a tag to sanitize.

  Returns:
    a safe tag, or an empty string if the tag is not allowed.
  """
  # Whitelist of allowed tags (lowercase)
  allowed_tags = [
      'a', 'b', 'big', 'br', 'center', 'code', 'em', 'h1', 'h2', 'h3',
      'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li', 'ol', 'p', 's', 'small',
      'span', 'strong', 'table', 'td', 'tr', 'u', 'ul',
  ]

  # Whitelist of safe attributes (lowercase) — anything not here is stripped
  allowed_attributes = [
      'alt', 'class', 'color', 'colspan', 'height', 'href', 'id',
      'rowspan', 'src', 'style', 'title', 'width',
  ]

  # Pass through closing tags for allowed tags
  if t.startswith('</'):
    # Extract the tag name from the closing tag
    close_tag_name = t[2:].rstrip('>').strip().lower()
    if close_tag_name in allowed_tags:
      return t
    return ''  # block disallowed closing tags

  m = TAG_RE.match(t)
  if m is None:
    # FIX: block malformed tags entirely instead of passing them through
    return ''

  tag_name = m.group(1).lower()  # FIX: lowercase comparison
  if tag_name not in allowed_tags:
    return ''  # FIX: block disallowed tags entirely

  # FIX: Strip any attribute not on the whitelist.
  # Parse attributes and only rebuild the ones that are explicitly allowed.
  # This prevents ALL event handlers (onclick, onmouseover, onload, etc.)
  # from passing through, regardless of case.
  attr_re = re.compile(
      r'\s+([\w-]+)'           # attribute name
      r'(?:\s*=\s*'            # optional = value
      r'(?:"[^"]*"|\'[^\']*\'|[^\s>]*))?',  # quoted or unquoted value
      re.IGNORECASE
  )
  safe_tag = '<' + tag_name
  for attr_match in attr_re.finditer(t[m.end(1):]):
    attr_name = attr_match.group(1).lower()
    if attr_name in allowed_attributes:
      safe_tag += attr_match.group(0)  # keep the full matched attribute
  safe_tag += '>'
  return safe_tag
