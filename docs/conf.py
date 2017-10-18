#!/usr/bin/env python3

import os
import sys

import alabaster
import sphinx_rtd_theme

sys.path.insert(0, os.path.abspath('..'))

version_file = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'ptracer', '__init__.py')

with open(version_file, 'r') as f:
    for line in f:
        if line.startswith('__version__ ='):
            _, _, version = line.partition('=')
            version = version.strip(" \n'\"")
            break
    else:
        raise RuntimeError(
            'could not determine the version from ptracer/__init__.py')

# -- General configuration ------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
]

add_module_names = False

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
project = 'ptracer'
copyright = '2017-present, Pinterest Inc'
author = 'Pinterest Inc.'
release = version
language = None
exclude_patterns = ['_build']
pygments_style = 'sphinx'
todo_include_todos = False
suppress_warnings = ['image.nonlocal_uri']

# -- Options for HTML output ----------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_theme_path = [alabaster.get_path()]
html_title = 'Ptracer Documentation'
html_short_title = 'ptracer'
html_static_path = []
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
    ]
}
html_show_sourcelink = False
html_show_sphinx = False
html_show_copyright = True
html_context = {
    'css_files': [
    ],
}
htmlhelp_basename = 'ptracerdoc'


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {}

latex_documents = [
    (master_doc, 'ptracer.tex', 'Ptracer Documentation',
     author, 'manual'),
]


# -- Options for manual page output ---------------------------------------

man_pages = [
    (master_doc, 'ptracer', 'Ptracer Documentation',
     [author], 1)
]


# -- Options for Texinfo output -------------------------------------------

texinfo_documents = [
    (master_doc, 'ptracer', 'Ptracer Documentation',
     author, 'ptracer',
     'Ptracer is a library providing on-demand system call tracing in '
     'Python programs.',
     'Miscellaneous'),
]

# -- Options for intersphinx ----------------------------------------------

intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}
