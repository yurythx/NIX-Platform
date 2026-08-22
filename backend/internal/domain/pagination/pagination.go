// Package pagination provides a shared page/page_size contract for every
// list endpoint in the platform, enforcing an upper bound so no handler can
// accidentally return an unbounded listing.
package pagination

const (
	DefaultPage     = 1
	DefaultPageSize = 20
	// AbsoluteMaxPageSize is the hard ceiling applied even if a caller's
	// configured MaxPageSize is set higher by mistake.
	AbsoluteMaxPageSize = 200
)

// Params is a validated, bounded page request.
type Params struct {
	Page     int
	PageSize int
}

// New builds Params from raw (possibly zero/absent) query values, clamping
// page to >=1 and pageSize to [1, maxPageSize]. maxPageSize <= 0 falls back
// to AbsoluteMaxPageSize.
func New(page, pageSize, maxPageSize int) Params {
	if page < 1 {
		page = DefaultPage
	}
	if maxPageSize <= 0 || maxPageSize > AbsoluteMaxPageSize {
		maxPageSize = AbsoluteMaxPageSize
	}
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return Params{Page: page, PageSize: pageSize}
}

// Offset returns the SQL OFFSET for these params.
func (p Params) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// Limit returns the SQL LIMIT for these params.
func (p Params) Limit() int {
	return p.PageSize
}

// Meta is the pagination metadata returned in the response envelope's
// "meta" field.
type Meta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalItems int64 `json:"total_items"`
	TotalPages int   `json:"total_pages"`
}

// NewMeta computes Meta from the requested params and the total row count.
func NewMeta(p Params, totalItems int64) Meta {
	totalPages := 0
	if p.PageSize > 0 {
		totalPages = int((totalItems + int64(p.PageSize) - 1) / int64(p.PageSize))
	}
	return Meta{
		Page:       p.Page,
		PageSize:   p.PageSize,
		TotalItems: totalItems,
		TotalPages: totalPages,
	}
}
