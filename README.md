# 🏢 AcessoApartamentos

Sistema de controle de acesso para apartamentos usando MySQL. Gerencia usuários, tokens de 5 dígitos e auditoria de entradas, garantindo segurança e regras específicas para Admin e Síndico (1 de cada permitido).

---

## 🔹 Estrutura do Banco

- **Banco:** `AcessoApartamentos` (criado do zero via `DROP DATABASE IF EXISTS`)  
- **Tabelas principais:**  
  - `TipoUsuario` → Morador, Admin, Síndico  
  - `Usuario` → Dados pessoais, senha SHA-256, tipo e status  
  - `Token` → Token de 5 dígitos, ativo/inativo, data de criação  
  - `Auditoria` → Registro de todas as tentativas de acesso  

- **Triggers:**  
  - Convertem senha pura (5 dígitos) para SHA-256  
  - Bloqueiam mais de 1 Admin ou Síndico  

---

## 🚪 Como Funciona

- Usuário tenta acessar com um token de 5 dígitos  
- Procedure `verificar_ou_criar_token(token_input)` verifica:
  - Token existente e ativo → `Permitida`  
  - Token inativo → `Negada`  
  - Token inexistente → `Negada`  
- Todas as tentativas são registradas em `Auditoria`

---

## 🧪 Testes Rápidos

### Tokens válidos
```sql
CALL verificar_ou_criar_token('12345'); -- João
CALL verificar_ou_criar_token('54321'); -- Leticia
CALL verificar_ou_criar_token('99999'); -- Carlos
```

###Tokens inexistentes
```sql
CALL verificar_ou_criar_token('11111');
CALL verificar_ou_criar_token('22222');
```

### Tokens inválidos (menos de 5 dígitos)
```sql
CALL verificar_ou_criar_token('1234');
CALL verificar_ou_criar_token('12');
CALL verificar_ou_criar_token('1');
```

### Tokens inativos
```sql
UPDATE Token SET ic_ativo = FALSE WHERE token_hash = '12345';
CALL verificar_ou_criar_token('12345');
```

## ✅ Benefícios
-Senhas seguras com SHA-256
-Controle rígido de Admin e Síndico
-Auditoria completa de acesso
-Testes rápidos com dados iniciais
