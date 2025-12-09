-- =====================================================
-- BANCO DE DADOS
-- =====================================================
DROP DATABASE IF EXISTS AcessoApartamentos;
CREATE DATABASE AcessoApartamentos;
USE AcessoApartamentos;

-- =====================================================
-- TABELA: TipoUsuario
-- =====================================================
CREATE TABLE TipoUsuario (
    id_tipo INT PRIMARY KEY AUTO_INCREMENT,
    nome_tipo VARCHAR(50) NOT NULL UNIQUE
);

-- =====================================================
-- TABELA: Usuario
-- =====================================================
CREATE TABLE Usuario (
    id_usuario INT PRIMARY KEY AUTO_INCREMENT,
    nm_usuario VARCHAR(100) NOT NULL,
    ds_senha CHAR(64) NOT NULL,        -- HASH SHA-256
    ds_senha_pura CHAR(5) NOT NULL,    -- APENAS PARA TESTES
    nr_cpf CHAR(11) UNIQUE NOT NULL,
    nr_apartamento INT NOT NULL,
    ic_ativo BOOLEAN DEFAULT TRUE,
    id_tipo INT NOT NULL,
    FOREIGN KEY (id_tipo) REFERENCES TipoUsuario(id_tipo) ON DELETE CASCADE
);

-- =====================================================
-- TABELA: Token  (5 dígitos)
-- =====================================================
CREATE TABLE Token (
    id_token INT PRIMARY KEY AUTO_INCREMENT,
    id_usuario INT NOT NULL,
    token_hash CHAR(5) UNIQUE NOT NULL,
    ic_ativo BOOLEAN DEFAULT TRUE,
    data_criacao DATETIME NOT NULL DEFAULT NOW(),
    FOREIGN KEY (id_usuario) REFERENCES Usuario(id_usuario) ON DELETE CASCADE
);

-- =====================================================
-- TABELA: Auditoria
-- =====================================================
CREATE TABLE Auditoria (
    id_auditoria INT PRIMARY KEY AUTO_INCREMENT,
    id_usuario INT NULL,
    id_token INT NULL,
    token_acesso VARCHAR(255) NOT NULL,
    data_acesso DATETIME NOT NULL DEFAULT NOW(),
    acao ENUM('Permitida', 'Negada') NOT NULL,
    FOREIGN KEY (id_usuario) REFERENCES Usuario(id_usuario) ON DELETE CASCADE,
    FOREIGN KEY (id_token) REFERENCES Token(id_token) ON DELETE CASCADE
);

-- =====================================================
-- TRIGGERS: Hash da senha
-- =====================================================

DELIMITER $$

CREATE TRIGGER trg_hash_senha_before_insert
BEFORE INSERT ON Usuario
FOR EACH ROW
BEGIN
    IF LENGTH(NEW.ds_senha_pura) <> 5 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'A senha deve ter exatamente 5 dígitos.';
    END IF;

    SET NEW.ds_senha = SHA2(NEW.ds_senha_pura, 256);
END$$


CREATE TRIGGER trg_hash_senha_before_update
BEFORE UPDATE ON Usuario
FOR EACH ROW
BEGIN
    IF NEW.ds_senha_pura <> OLD.ds_senha_pura THEN
        IF LENGTH(NEW.ds_senha_pura) <> 5 THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'A senha deve ter exatamente 5 dígitos.';
        END IF;

        SET NEW.ds_senha = SHA2(NEW.ds_senha_pura, 256);
    END IF;
END$$

DELIMITER ;

-- =====================================================
-- TRIGGERS: Limitar a 1 Admin e 1 Síndico
-- id_tipo = 2 → Admin
-- id_tipo = 3 → Sindico
-- =====================================================

DELIMITER $$

CREATE TRIGGER trg_limite_admin_insert
BEFORE INSERT ON Usuario
FOR EACH ROW
BEGIN
    IF NEW.id_tipo = 2 THEN
        IF (SELECT COUNT(*) FROM Usuario WHERE id_tipo = 2) >= 1 THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Só é permitido 1 usuário Admin no sistema.';
        END IF;
    END IF;
END$$


CREATE TRIGGER trg_limite_sindico_insert
BEFORE INSERT ON Usuario
FOR EACH ROW
BEGIN
    IF NEW.id_tipo = 3 THEN
        IF (SELECT COUNT(*) FROM Usuario WHERE id_tipo = 3) >= 1 THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Só é permitido 1 usuário Síndico no sistema.';
        END IF;
    END IF;
END$$


CREATE TRIGGER trg_limite_admin_update
BEFORE UPDATE ON Usuario
FOR EACH ROW
BEGIN
    IF NEW.id_tipo = 2 AND OLD.id_tipo <> 2 THEN
        IF (SELECT COUNT(*) FROM Usuario WHERE id_tipo = 2) >= 1 THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Só é permitido 1 usuário Admin no sistema.';
        END IF;
    END IF;
END$$


CREATE TRIGGER trg_limite_sindico_update
BEFORE UPDATE ON Usuario
FOR EACH ROW
BEGIN
    IF NEW.id_tipo = 3 AND OLD.id_tipo <> 3 THEN
        IF (SELECT COUNT(*) FROM Usuario WHERE id_tipo = 3) >= 1 THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Só é permitido 1 usuário Síndico no sistema.';
        END IF;
    END IF;
END$$

DELIMITER ;

-- =====================================================
-- DADOS INICIAIS
-- =====================================================

INSERT INTO TipoUsuario (nome_tipo) VALUES
('Morador'),
('Admin'),
('Sindico');

INSERT INTO Usuario (nm_usuario, ds_senha_pura, nr_cpf, nr_apartamento, id_tipo)
VALUES
('João Lacerda',  '00099', '01928763567', 101, 1),
('Leticia Souza', '99927', '11109872653', 102, 2),
('Carlos Lima',   '15624', '83967777878', 103, 3);

INSERT INTO Token (id_usuario, token_hash) VALUES
(1, '12345'),
(2, '54321'),
(3, '99999');

-- =====================================================
-- PROCEDURE DE ACESSO COM TOKEN
-- =====================================================

DELIMITER $$

CREATE PROCEDURE verificar_ou_criar_token(IN token_input VARCHAR(5))
BEGIN
    DECLARE v_id_usuario INT;
    DECLARE v_id_token INT;
    DECLARE v_ativo BOOLEAN;
    DECLARE v_nome VARCHAR(100);

    DECLARE CONTINUE HANDLER FOR NOT FOUND 
        SET v_id_usuario = NULL, v_id_token = NULL, v_ativo = NULL;

    SELECT T.id_usuario, T.id_token, T.ic_ativo, U.nm_usuario
    INTO v_id_usuario, v_id_token, v_ativo, v_nome
    FROM Token T
    LEFT JOIN Usuario U ON U.id_usuario = T.id_usuario
    WHERE T.token_hash = token_input;

    IF v_id_token IS NOT NULL THEN
        
        IF v_ativo = TRUE THEN
            INSERT INTO Auditoria (id_usuario, id_token, token_acesso, acao)
            VALUES (v_id_usuario, v_id_token, token_input, 'Permitida');

            SELECT CONCAT('Bem-vindo(a) ', v_nome, '! Acesso permitido.') AS mensagem;

        ELSE
            INSERT INTO Auditoria (id_usuario, id_token, token_acesso, acao)
            VALUES (v_id_usuario, v_id_token, token_input, 'Negada');

            SELECT CONCAT('Token inativo para o usuário ', v_nome) AS mensagem;
        END IF;

    ELSE
        INSERT INTO Auditoria (id_usuario, id_token, token_acesso, acao)
        VALUES (NULL, NULL, token_input, 'Negada');

        SELECT 'Token inexistente' AS mensagem;
    END IF;

END$$

DELIMITER ;

-- =====================================================
-- TESTES
-- =====================================================

-- ============================
-- 1. TOKENS VÁLIDOS
-- ============================
CALL verificar_ou_criar_token('12345');
CALL verificar_ou_criar_token('54321');
CALL verificar_ou_criar_token('99999');

-- ============================
-- 2. TOKENS INEXISTENTES
-- ============================
CALL verificar_ou_criar_token('11111');
CALL verificar_ou_criar_token('22222');
CALL verificar_ou_criar_token('00001');

-- ============================
-- 3. TOKENS INVÁLIDOS
-- ============================
CALL verificar_ou_criar_token('1234');
CALL verificar_ou_criar_token('123');
CALL verificar_ou_criar_token('12');
CALL verificar_ou_criar_token('1');

