// Package pagination fornece um contrato compartilhado de page/page_size
// para todo endpoint de listagem da plataforma, impondo um teto superior
// para que nenhum handler consiga acidentalmente retornar uma listagem sem
// limite (o que, com uma tabela grande, derrubaria a API ou o cliente).
package pagination

const (
	DefaultPage     = 1
	DefaultPageSize = 20
	// AbsoluteMaxPageSize é o teto rígido aplicado mesmo se o
	// MaxPageSize configurado por quem chama for definido mais alto por
	// engano.
	AbsoluteMaxPageSize = 200
)

// Params é uma requisição de página já validada e limitada.
type Params struct {
	Page     int
	PageSize int
}

// New constrói Params a partir de valores brutos de query (possivelmente
// zero/ausentes), limitando page a >=1 e pageSize a [1, maxPageSize].
// maxPageSize <= 0 cai no padrão AbsoluteMaxPageSize.
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

// Offset retorna o OFFSET SQL correspondente a estes params.
func (p Params) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// Limit retorna o LIMIT SQL correspondente a estes params.
func (p Params) Limit() int {
	return p.PageSize
}

// Meta são os metadados de paginação retornados no campo "meta" do
// envelope de resposta (§27/§46).
type Meta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalItems int64 `json:"total_items"`
	TotalPages int   `json:"total_pages"`
}

// NewMeta calcula Meta a partir dos params requisitados e da contagem
// total de linhas.
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
