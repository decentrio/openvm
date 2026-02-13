use core::fmt::Debug;
use std::marker::PhantomData;

use openvm_stark_backend::p3_field::{Field, FieldExtensionAlgebra, PrimeField};
use serde::{Deserialize, Serialize};

use self::opcodes::ConstraintOpcode;
use crate::{
    ir::{Config, DslIr},
    prelude::TracedVec,
};

#[cfg(feature = "halo2-compiler")]
pub mod halo2;

pub mod gnark;

pub mod opcodes;

/// A constraint is an operation and a list of nested arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub opcode: ConstraintOpcode,
    pub args: Vec<Vec<String>>,
}

/// The backend for the constraint compiler.
#[derive(Debug, Clone, Default)]
pub struct ConstraintCompiler<C: Config> {
    pub allocator: usize,
    pub phantom: PhantomData<C>,
}

impl<C: Config + Debug> ConstraintCompiler<C> {
    /// Allocate a new variable name in the constraint system.
    pub fn alloc_id(&mut self) -> String {
        let id = self.allocator;
        self.allocator += 1;
        format!("backend{}", id)
    }

    /// Allocates a variable in the constraint system.
    pub fn alloc_v(&mut self, constraints: &mut Vec<Constraint>, value: C::N) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmV,
            args: vec![
                vec![tmp_id.clone()],
                vec![value.as_canonical_biguint().to_string()],
            ],
        });
        tmp_id
    }

    /// Allocate a felt in the constraint system.
    pub fn alloc_f(&mut self, constraints: &mut Vec<Constraint>, value: C::F) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmF,
            args: vec![
                vec![tmp_id.clone()],
                vec![value.as_canonical_biguint().to_string()],
            ],
        });
        tmp_id
    }

    /// Allocate an extension element in the constraint system.
    pub fn alloc_e(&mut self, constraints: &mut Vec<Constraint>, value: C::EF) -> String {
        let tmp_id = self.alloc_id();
        constraints.push(Constraint {
            opcode: ConstraintOpcode::ImmE,
            args: vec![
                vec![tmp_id.clone()],
                value
                    .as_base_slice()
                    .iter()
                    .map(|x| x.as_canonical_biguint().to_string())
                    .collect(),
            ],
        });
        tmp_id
    }

    /// Emit the constraints from a list of operations in the DSL.
    pub fn emit(&mut self, operations: TracedVec<DslIr<C>>) -> Vec<Constraint> {
        let mut constraints: Vec<Constraint> = Vec::new();
        for (instruction, _) in operations {
            match instruction {
                DslIr::ImmV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmV,
                    args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                }),
                DslIr::ImmF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmF,
                    args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                }),
                DslIr::ImmE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::ImmE,
                    args: vec![
                        vec![a.id()],
                        b.as_base_slice()
                            .iter()
                            .map(|x| x.as_canonical_biguint().to_string())
                            .collect(),
                    ],
                }),
                DslIr::AddV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddVI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddVI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            vec![c.as_canonical_biguint().to_string()],
                        ],
                    });
                }
                DslIr::AddF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddFI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddFI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            vec![c.as_canonical_biguint().to_string()],
                        ],
                    });
                }
                DslIr::AddE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AddEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::AddEFI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddEFI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            vec![c.as_canonical_biguint().to_string()],
                        ],
                    });
                }
                DslIr::AddEI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddEI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            c.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                        ],
                    });
                }
                DslIr::AddEFFI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AddEFFI,
                        args: vec![
                            vec![a.id()],
                            c.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                            vec![b.id()],
                        ],
                    });
                }
                DslIr::SubV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::SubEI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubEI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            c.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                        ],
                    });
                }
                DslIr::SubVIN(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubVIN,
                        args: vec![
                            vec![a.id()],
                            vec![b.as_canonical_biguint().to_string()],
                            vec![c.id()],
                        ],
                    });
                }
                DslIr::SubEIN(a, b, c) => {
                    let tmp = self.alloc_e(&mut constraints, b);
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::SubEIN,
                        args: vec![
                            vec![a.id()],
                            b.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                            vec![c.id()],
                        ],
                    });
                }
                DslIr::SubEFI(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::SubEFI,
                    args: vec![
                        vec![a.id()],
                        vec![b.id()],
                        vec![c.as_canonical_biguint().to_string()],
                    ],
                }),
                DslIr::MulV(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulV,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulVI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulVI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            vec![c.as_canonical_biguint().to_string()],
                        ],
                    });
                }
                DslIr::MulF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulFI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulFI,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            vec![c.as_canonical_biguint().to_string()],
                        ],
                    });
                }
                DslIr::MulE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulEI(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::MulE,
                        args: vec![
                            vec![a.id()],
                            vec![b.id()],
                            c.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                        ],
                    });
                }
                DslIr::MulEF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulEF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::MulEFI(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::MulEFI,
                    args: vec![
                        vec![a.id()],
                        vec![b.id()],
                        vec![c.as_canonical_biguint().to_string()],
                    ],
                }),
                DslIr::DivF(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivF,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::DivFIN(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::DivFIN,
                        args: vec![
                            vec![a.id()],
                            vec![b.as_canonical_biguint().to_string()],
                            vec![c.id()],
                        ],
                    });
                }
                DslIr::DivE(a, b, c) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::DivE,
                    args: vec![vec![a.id()], vec![b.id()], vec![c.id()]],
                }),
                DslIr::DivEIN(a, b, c) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::DivE,
                        args: vec![
                            vec![a.id()],
                            b.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                            vec![c.id()],
                        ],
                    });
                }
                DslIr::NegE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::NegE,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::CastFV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CastFV,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::CircuitNum2BitsF(value, output) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitNum2BitsF,
                    args: vec![output.iter().map(|x| x.id()).collect(), vec![value.id()]],
                }),
                DslIr::CircuitVarTo64BitsF(value, output) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitVarTo64BitsF,
                    args: vec![vec![value.id()], output.iter().map(|x| x.id()).collect()],
                }),
                DslIr::CircuitPoseidon2Permute(state) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitPoseidon2Permute,
                    args: state.iter().map(|x| vec![x.id()]).collect(),
                }),
                DslIr::CircuitSelectV(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::CircuitSelectV,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIr::CircuitSelectF(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::CircuitSelectF,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIr::CircuitSelectE(cond, a, b, out) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::CircuitSelectE,
                        args: vec![vec![out.id()], vec![cond.id()], vec![a.id()], vec![b.id()]],
                    });
                }
                DslIr::CircuitExt2Felt(a, b) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::CircuitExt2Felt,
                        args: vec![
                            vec![a[0].id()],
                            vec![a[1].id()],
                            vec![a[2].id()],
                            vec![a[3].id()],
                            vec![b.id()],
                        ],
                    });
                }
                DslIr::AssertEqV(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqV,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertEqVI(a, b) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqVI,
                        args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                    });
                }
                DslIr::AssertEqF(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqF,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertEqFI(a, b) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqFI,
                        args: vec![vec![a.id()], vec![b.as_canonical_biguint().to_string()]],
                    });
                }
                DslIr::AssertEqE(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::AssertEqE,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::AssertEqEI(a, b) => {
                    constraints.push(Constraint {
                        opcode: ConstraintOpcode::AssertEqEI,
                        args: vec![
                            vec![a.id()],
                            b.as_base_slice()
                                .iter()
                                .map(|x| x.as_canonical_biguint().to_string())
                                .collect(),
                        ],
                    });
                }
                DslIr::PrintV(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintV,
                    args: vec![vec![a.id()]],
                }),
                DslIr::PrintF(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintF,
                    args: vec![vec![a.id()]],
                }),
                DslIr::PrintE(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::PrintE,
                    args: vec![vec![a.id()]],
                }),
                DslIr::WitnessVar(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::WitnessVar,
                    args: vec![vec![a.id()], vec![b.to_string()]],
                }),
                DslIr::WitnessFelt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::WitnessFelt,
                    args: vec![vec![a.id()], vec![b.to_string()]],
                }),
                DslIr::WitnessExt(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::WitnessExt,
                    args: vec![vec![a.id()], vec![b.to_string()]],
                }),
                DslIr::CircuitFelts2Ext(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitFelts2Ext,
                    args: vec![
                        vec![b.id()],
                        vec![a[0].id()],
                        vec![a[1].id()],
                        vec![a[2].id()],
                        vec![a[3].id()],
                    ],
                }),
                DslIr::CircuitFeltReduce(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitFeltReduce,
                    args: vec![vec![a.id()]],
                }),
                DslIr::CircuitExtReduce(a) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitExtReduce,
                    args: vec![vec![a.id()]],
                }),
                DslIr::CircuitLessThan(a, b) => constraints.push(Constraint {
                    opcode: ConstraintOpcode::CircuitLessThan,
                    args: vec![vec![a.id()], vec![b.id()]],
                }),
                DslIr::CycleTrackerStart(..) => {}
                DslIr::CycleTrackerEnd(..) => {}
                DslIr::Publish(val, index) => {}
                _ => panic!("unsupported {:?}", instruction),
            };
        }
        constraints
    }
}
