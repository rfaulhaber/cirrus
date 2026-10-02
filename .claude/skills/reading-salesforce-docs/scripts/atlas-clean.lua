-- Pandoc filter for the DITA-generated HTML of atlas pages
-- (developer.salesforce.com/docs/atlas.*) and Salesforce Help articles.
--
-- Atlas reference pages are mostly field tables whose cells hold lists and
-- paragraphs. With their DITA attributes left on, pandoc's gfm writer emits
-- every table as attribute-heavy HTML, and with raw HTML disabled it replaces
-- each one with a bare "[TABLE]". Clearing the attributes lets the writer use
-- pipe tables where cells are simple and compact HTML where they are not.
--
-- SFDOC_LINK_ROOT is the origin the page came from, for root-relative links.

local empty = pandoc.Attr()
local ATLAS_BASE = "https://developer.salesforce.com/docs/"
local HELP_ARTICLE = "https://help.salesforce.com/s/articleView?id=%s&type=5"
local LINK_ROOT = os.getenv("SFDOC_LINK_ROOT") or "https://developer.salesforce.com"

function Span(el) return el.content end
function Div(el) return el.content end
function Image(el) return {} end
function Code(el) el.attr = empty return el end
function Header(el) el.attr = empty return el end

function CodeBlock(el)
  local lang
  for _, class in ipairs(el.classes) do
    lang = lang or class:match("^brush:(.+)$")
  end
  el.attr = pandoc.Attr("", lang and { lang } or {})
  return el
end

-- Atlas cross-references are book-relative ("atlas.en-us.api_meta.meta/api_meta/x.htm")
-- and carry the target's abstract as a tooltip title; Help cross-references use the
-- legacy HTViewHelpDoc path, which now only redirects to the article page.
function Link(el)
  el.attr = empty
  el.title = ""
  local help_id = el.target:match("^/apex/HTViewHelpDoc%?id=([^&]+)")
  if help_id then
    el.target = HELP_ARTICLE:format(help_id)
  elseif el.target:match("^atlas%.") then
    el.target = ATLAS_BASE .. el.target
  elseif el.target:match("^/") then
    el.target = LINK_ROOT .. el.target
  end
  return el
end

local function clean_rows(rows)
  for _, row in ipairs(rows) do
    row.attr = empty
    for _, cell in ipairs(row.cells) do cell.attr = empty end
  end
end

function Table(el)
  el.attr = empty
  for i, spec in ipairs(el.colspecs) do el.colspecs[i] = { spec[1], pandoc.ColWidthDefault } end
  el.head.attr = empty
  clean_rows(el.head.rows)
  for _, body in ipairs(el.bodies) do
    body.attr = empty
    clean_rows(body.head)
    clean_rows(body.body)
  end
  el.foot.attr = empty
  clean_rows(el.foot.rows)
  return el
end
