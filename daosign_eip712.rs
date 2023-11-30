#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[openbrush::contract]
mod daosign_eip712 {

    #[ink(storage)]
    pub struct DAOsignEIP712 {}

    impl DAOsignEIP712 {
        #[ink(constructor)]
        pub fn new() -> Self {
            ink::env::debug_println!("created new instance at {}", Self::env().block_number());
            Self {}
        }
    }

    impl DAOsignEIP712 {
        #[ink(message)]
        pub fn hash(&self) -> [u8; 32] {
            [1; 32]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn hash() {
            let instance = DAOsignEIP712::new();
            assert_eq!(instance.hash(), [1; 32]);
        }
    }
}
