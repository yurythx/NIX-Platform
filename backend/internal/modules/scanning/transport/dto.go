package transport

import (
	"time"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// FindingResponse é o formato público de um achado persistido — mesmo
// padrão de integrations/transport/dto.go: o domain.PersistedFinding
// nunca é serializado direto (seus campos não têm tag json, então
// sairiam em PascalCase, inconsistente com o resto da API, que é sempre
// snake_case).
type FindingResponse struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	Scanner       string    `json:"scanner"`
	Target        string    `json:"target"`
	FindingID     string    `json:"finding_id"`
	OWASPCategory string    `json:"owasp_category"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	File          string    `json:"file"`
	Line          int       `json:"line"`
	CreatedAt     time.Time `json:"created_at"`
}

func toFindingResponse(f domain.PersistedFinding) FindingResponse {
	return FindingResponse{
		ID:            f.RecordID.String(),
		ScanID:        f.ScanID.String(),
		Scanner:       f.Scanner,
		Target:        f.Target,
		FindingID:     f.Finding.ID,
		OWASPCategory: f.OWASPCategory,
		Severity:      string(f.Severity),
		Description:   f.Description,
		File:          f.File,
		Line:          f.Line,
		CreatedAt:     f.CreatedAt,
	}
}

func toFindingResponses(list []domain.PersistedFinding) []FindingResponse {
	out := make([]FindingResponse, 0, len(list))
	for _, f := range list {
		out = append(out, toFindingResponse(f))
	}
	return out
}
