# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Hello, ID Please"
project_copyright = "2024, Jaap Roes, Dennis Bunskoek, Thomas Kalverda, Wouter de Vries"
author = "Jaap Roes, Dennis Bunskoek, Thomas Kalverda, Wouter de Vries"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["myst_parser", "sphinx.ext.napoleon", "sphinx.ext.autodoc"]
myst_enable_extensions = ["colon_fence", "attrs_inline", "deflist"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

autodoc_mock_imports = ["django"]

myst_heading_anchors = 3

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
