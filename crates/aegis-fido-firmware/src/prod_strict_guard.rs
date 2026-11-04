//! GAP-04: Isolamento Estrito de `prod-strict` vs `test-mode`
//!
//! Garante que em compilações de produção (`prod-strict`), qualquer hook
//! de injeção de presença física (e.g. `TEST_UP`), bypasses de autorização
//! ou canais de teste sejam terminantemente proibidos tanto em tempo de
//! compilação quanto em tempo de execução.
//!
//! Clean Architecture, SOLID e Zero Mocks.

#[cfg(all(feature = "prod-strict", feature = "test-mode"))]
compile_error!(
    "SECURITY VIOLATION (GAP-04): Cannot enable 'test-mode' when building with 'prod-strict'. Software touch simulation hooks are strictly forbidden in production."
);

/// Indica se a flag de compilação restrita de produção está ativa.
pub const PROD_STRICT_ACTIVE: bool = cfg!(feature = "prod-strict");

/// Mensagem canônica de violação de política ao tentar usar toque simulado em produção.
pub const ERR_PROD_TOUCH_FORBIDDEN: &str =
    "SECURITY VIOLATION: Software touch simulation is strictly forbidden in production (GAP-04).";

/// Avalia se a simulação de presença física via software é permitida no build corrente.
///
/// Retorna `false` incondicionalmente se `prod-strict` estiver ativo.
/// Retorna `true` apenas se `test-mode` estiver ativo e `prod-strict` inativo.
#[inline]
pub fn is_software_touch_allowed() -> bool {
    #[cfg(feature = "prod-strict")]
    {
        false
    }
    #[cfg(not(feature = "prod-strict"))]
    {
        #[cfg(feature = "test-mode")]
        {
            true
        }
        #[cfg(not(feature = "test-mode"))]
        {
            false
        }
    }
}

/// Verifica a autorização de presença de software de forma fail-closed.
///
/// Retorna `Ok(())` se toque simulado for permitido pelo profile, ou `Err(&str)` caso contrário.
pub fn verify_software_touch_allowed() -> Result<(), &'static str> {
    if is_software_touch_allowed() {
        Ok(())
    } else {
        Err(ERR_PROD_TOUCH_FORBIDDEN)
    }
}

/// Validador de canal de teste para gates de comando.
pub struct ProductionIsolationGate;

impl ProductionIsolationGate {
    /// Valida se um comando de teste pode ser executado.
    pub fn can_execute_test_command(command_name: &str) -> bool {
        if !is_software_touch_allowed() {
            log::warn!(
                "[PROD_GUARD] Rejected test command '{}' due to production strict policy",
                command_name
            );
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_touch_policy_consistency() {
        if PROD_STRICT_ACTIVE {
            assert!(!is_software_touch_allowed());
            assert!(verify_software_touch_allowed().is_err());
            assert!(!ProductionIsolationGate::can_execute_test_command(
                "TEST_UP"
            ));
        } else {
            // Em builds regulares sem test-mode, também deve ser false
            #[cfg(not(feature = "test-mode"))]
            {
                assert!(!is_software_touch_allowed());
                assert!(verify_software_touch_allowed().is_err());
            }
        }
    }
}
