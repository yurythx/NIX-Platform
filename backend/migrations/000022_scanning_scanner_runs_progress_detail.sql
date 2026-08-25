-- +goose Up
-- Pedido do usuário: "quero saber em tempo real como está rodando o
-- ataque" — start/finish (StartScannerRun/FinishScannerRun, migração
-- 000016) já dizem QUE um scanner está rodando, mas não O QUÊ ele está
-- fazendo agora. Só o ZAP (spider + scan ativo, minutos de duração) tem
-- fases internas que valem a pena expor; os demais scanners terminam
-- rápido o bastante pra "rodando" sozinho já ser feedback suficiente —
-- por isso uma coluna de texto livre, opcional, nunca um novo status.
ALTER TABLE scanning_scanner_runs ADD COLUMN progress_detail TEXT;

-- +goose Down
ALTER TABLE scanning_scanner_runs DROP COLUMN progress_detail;
