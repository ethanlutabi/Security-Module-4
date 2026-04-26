"""Gruyere Template Language, part of Gruyere, a web application with holes.

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
import cgi
import logging
import operator
import os
import pprint
import re
import sys

# our modules
import gruyere
import sanitize


def ExpandTemplate(template, specials, params, name=''):
  """Expands a template.

  Args:
    template: a string template.
    specials: a dict of special values.
    params: a dict of parameter values.
    name: the name of the _this object.

  Returns:
    the expanded template.
  """
  t = _ExpandBlocks(template, specials, params, name)
  t = _ExpandVariables(t, specials, params, name)
  return t


BLOCK_OPEN = '[['
END_BLOCK_OPEN = '[[/'
BLOCK_CLOSE = ']]'


def _ExpandBlocks(template, specials, params, name):
  """Expands all the blocks in a template."""
  result = []
  rest = template
  while rest:
    tag, before_tag, after_tag = _FindTag(rest, BLOCK_OPEN, BLOCK_CLOSE)
    if tag is None:
      break
    end_tag = END_BLOCK_OPEN + tag + BLOCK_CLOSE
    before_end = rest.find(end_tag, after_tag)
    if before_end < 0:
      break
    after_end = before_end + len(end_tag)

    result.append(rest[:before_tag])
    block = rest[after_tag:before_end]
    result.append(_ExpandBlock(tag, block, specials, params, name))
    rest = rest[after_end:]
  return ''.join(result) + rest


VAR_OPEN = '{{'
VAR_CLOSE = '}}'


def _ExpandVariables(template, specials, params, name):
  """Expands all the variables in a template."""
  result = []
  rest = template
  while rest:
    tag, before_tag, after_tag = _FindTag(rest, VAR_OPEN, VAR_CLOSE)
    if tag is None:
      break
    result.append(rest[:before_tag])
    result.append(str(_ExpandVariable(tag, specials, params, name)))
    rest = rest[after_tag:]
  return ''.join(result) + rest


FOR_TAG = 'for'
IF_TAG = 'if'
INCLUDE_TAG = 'include'


def _ExpandBlock(tag, template, specials, params, name):
  """Expands a single template block."""
  tag_type, block_var = tag.split(':', 1)
  if tag_type == INCLUDE_TAG:
    return _ExpandInclude(tag, block_var, template, specials, params, name)
  elif tag_type == IF_TAG:
    block_data = _ExpandVariable(block_var, specials, params, name)
    if block_data:
      return ExpandTemplate(template, specials, params, name)
    return ''
  elif tag_type == FOR_TAG:
    block_data = _ExpandVariable(block_var, specials, params, name)
    return _ExpandFor(tag, template, specials, block_data)
  else:
    _Log('Error: Invalid block: %s' % (tag,))
    return ''


def _ExpandInclude(_, filename, template, specials, params, name):
  """Expands an include block (or insert the template on an error)."""
  result = ''
  # replace /s with local file system equivalent
  fname = os.sep + filename.replace('/', os.sep)
  f = None
  try:
    try:
      f = gruyere._Open(gruyere.RESOURCE_PATH, fname)
      result = f.read()
    except IOError:
      _Log('Error: missing filename: %s' % (filename,))
      result = template
  finally:
    if f: f.close()
  return ExpandTemplate(result, specials, params, name)


def _ExpandFor(tag, template, specials, block_data):
  """Expands a for block iterating over the block_data."""
  result = []
  if operator.isMappingType(block_data):
    for v in block_data:
      result.append(ExpandTemplate(template, specials, block_data[v], v))
  elif operator.isSequenceType(block_data):
    for i in xrange(len(block_data)):
      result.append(ExpandTemplate(template, specials, block_data[i], str(i)))
  else:
    _Log('Error: Invalid type: %s' % (tag,))
    return ''
  return ''.join(result)


# FIX (Stored XSS via HTML Attribute - Challenge 4):
# The original code used cgi.escape(str(value)) for the :text escaper.
# cgi.escape only escapes <, >, and & by default. Even with the optional
# quote=True parameter, it only escapes double quotes — NOT single quotes.
# Since home.gtl uses single-quoted attributes (style='color:{{color:text}}'),
# an attacker could inject a single quote to break out of the attribute
# and add malicious event handlers like onmouseover='alert(1)'.
#
# Fix: Replace cgi.escape with _EscapeTextToHtml which escapes ALL dangerous
# characters including both single quotes (&#39;) and double quotes (&quot;).

def _EscapeTextToHtml(value):
  """Safely escapes a value for insertion into HTML, including inside attributes.

  Escapes all HTML metacharacters including both single and double quotes,
  preventing XSS via attribute injection regardless of quote style used.

  Args:
    value: The string value to escape.

  Returns:
    The escaped string safe for use in HTML body or attribute context.
  """
  meta_chars = {
      '"':  '&quot;',
      "'":  '&#39;',   # cgi.escape never escapes single quotes — this is the fix
      '&':  '&amp;',
      '<':  '&lt;',
      '>':  '&gt;',
  }
  escaped = ''
  for char in str(value):
    escaped += meta_chars.get(char, char)
  return escaped


# FIX (Stored XSS via Attribute - color field):
# Even with correct HTML escaping, CSS expressions like expression(alert(1))
# in Internet Explorer can execute JavaScript via the style attribute.
# We add a color sanitiser that only allows safe color values.

SAFE_COLOR_RE = re.compile(r'^#?[a-zA-Z0-9]*$')

def _SanitizeColor(color):
  """Sanitizes a color value, returning 'invalid' if it contains unsafe content.

  Only allows color names (letters) or hex codes (#RRGGBB).
  This prevents CSS expression injection via the color field.

  Args:
    color: The color string to validate.

  Returns:
    The original color if safe, or 'invalid' otherwise.
  """
  if SAFE_COLOR_RE.match(str(color)):
    return str(color)
  return 'invalid'


def _ExpandVariable(var, specials, params, name, default=''):
  """Gets a variable value."""
  if var.startswith('#'):  # this is a comment.
    return ''

  # Strip out leading ! which negates value
  inverted = var.startswith('!')
  if inverted:
    var = var[1:]

  # Strip out trailing :<escaper>
  escaper_name = None
  if var.find(':') >= 0:
    (var, escaper_name) = var.split(':', 1)

  value = _ExpandValue(var, specials, params, name, default)
  if inverted:
    value = not value

  # FIX: replaced cgi.escape with _EscapeTextToHtml for :text escaper
  # so that single quotes in attribute values are also escaped correctly.
  if escaper_name == 'text':
    value = _EscapeTextToHtml(str(value))       # FIX: was cgi.escape(str(value))
  elif escaper_name == 'html':
    value = sanitize.SanitizeHtml(str(value))
  elif escaper_name == 'color':                 # FIX: new :color escaper
    value = _SanitizeColor(value)
  elif escaper_name == 'pprint':  # for debugging
    value = '<pre>' + _EscapeTextToHtml(pprint.pformat(value)) + '</pre>'

  if value is None:
    value = ''
  return value


def _ExpandValue(var, specials, params, name, default):
  """Expand one value."""
  if var == '_key':
    return name
  elif var == '_this':
    return params
  if var.startswith('_'):
    value = specials
  else:
    value = params

  for v in var.split('.'):
    if v == '*_this':
      v = params
    if v.startswith('*'):
      v = _GetValue(specials['_params'], v[1:])
      if operator.isSequenceType(v):
        v = v[0]  # reduce repeated url param to single value
    value = _GetValue(value, str(v), default)
  return value


def _GetValue(collection, index, default=''):
  """Gets a single indexed value out of a collection."""
  if operator.isMappingType(collection) and index in collection:
    value = collection[index]
  elif (operator.isSequenceType(collection) and index.isdigit() and
        int(index) < len(collection)):
    value = collection[int(index)]
  else:
    value = default
  return value


def _Cond(test, if_true, if_false):
  """Substitute for 'if_true if test else if_false' in Python 2.4."""
  if test:
    return if_true
  else:
    return if_false


def _FindTag(template, open_marker, close_marker):
  """Finds a single tag."""
  open_pos = template.find(open_marker)
  close_pos = template.find(close_marker, open_pos)
  if open_pos < 0 or close_pos < 0 or open_pos > close_pos:
    return (None, None, None)
  return (template[open_pos + len(open_marker):close_pos],
          open_pos,
          close_pos + len(close_marker))


def _Log(message):
  logging.warning('%s', message)
  print >>sys.stderr, message
