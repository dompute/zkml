use std::{
  fs::File,
  io::{BufReader, Read},
};

use anyhow::Result;
use circuit_cli::CliOperator;
use halo2_proofs::{
  dev::MockProver,
  halo2curves::bn256::{Bn256, Fr, G1Affine},
  plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
  poly::{
    commitment::Params,
    kzg::{
      commitment::{KZGCommitmentScheme, ParamsKZG},
      multiopen::{ProverSHPLONK, VerifierSHPLONK},
      strategy::SingleStrategy,
    },
  },
  transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
  },
};
use rand::rngs::ThreadRng;
use serde_derive::{Deserialize, Serialize};
use zkml::{
  model::ModelCircuit,
  utils::{helpers::get_public_values, proving_kzg::verify_kzg},
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CliArgs {
  pub config_fname: Option<String>,
  pub inp_fname: Option<String>,
}

struct Operator;

struct MlParams {
  params: ParamsKZG<Bn256>,
  public_vals: Vec<Fr>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MlParamsSerde {
  params: Vec<u8>,
  public_vals: Vec<u8>,
}

fn main() -> Result<()> {
  env_logger::init();

  circuit_cli::run(Operator)?;
  Ok(())
}

impl CliArgs {
  pub fn gen_circuit(&self) -> ModelCircuit<Fr> {
    let config_fname = self
      .config_fname
      .as_ref()
      .map(|s| s.as_str())
      .unwrap_or("/data/model.msgpack");
    let inp_fname = self
      .inp_fname
      .as_ref()
      .map(|s| s.as_str())
      .unwrap_or("/data/inp.msgpack");
    ModelCircuit::<Fr>::generate_from_file(&config_fname, &inp_fname)
  }
}

impl CliOperator<CliArgs, CliArgs> for Operator {
  fn create_proof(
    &self,
    args: CliArgs,
    params_reader: Option<BufReader<File>>,
  ) -> circuit_cli::Result<(Vec<u8>, Vec<u8>)> {
    self.generate_ml_proof(args, params_reader, rand::thread_rng())
  }

  fn verify_proof(
    &self,
    args: CliArgs,
    params_reader: Option<BufReader<File>>,
    proof: &[u8],
  ) -> circuit_cli::Result<bool> {
    self.verify_ml_proof(
      args,
      params_reader.ok_or(circuit_cli::Error::CliLogicError(
        "params reader is none".to_string(),
      ))?,
      proof,
    )
  }
}

impl Operator {
  fn generate_ml_proof(
    &self,
    args: CliArgs,
    params_reader: Option<BufReader<File>>,
    rng: ThreadRng,
  ) -> circuit_cli::Result<(Vec<u8>, Vec<u8>)> {
    let circuit = args.gen_circuit();
    let k = circuit.k as u32;

    let params: ParamsKZG<Bn256>;
    if let Some(mut params_r) = params_reader {
      params = Params::read::<_>(&mut params_r)?;
    } else {
      params = ParamsKZG::<Bn256>::setup(k, rng.clone());
    }

    let vk = keygen_vk(&params, &circuit)
      .map_err(|e| circuit_cli::Error::CliLogicError(format!("keygen vk failed: {}", e)))?;
    let pk = keygen_pk(&params, vk, &circuit)
      .map_err(|e| circuit_cli::Error::CliLogicError(format!("keygen pk failed: {}", e)))?;

    let _prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    let public_vals: Vec<Fr> = get_public_values();

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<
      KZGCommitmentScheme<Bn256>,
      ProverSHPLONK<'_, Bn256>,
      Challenge255<G1Affine>,
      _,
      Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
      ModelCircuit<Fr>,
    >(
      &params,
      &pk,
      &[circuit],
      &[&[&public_vals]],
      rng,
      &mut transcript,
    )
    .unwrap();

    let proof = transcript.finalize();

    let strategy = SingleStrategy::new(&params);
    let transcript_read = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_kzg(
      &params,
      &pk.get_vk(),
      strategy,
      &public_vals,
      transcript_read,
    );

    Ok((proof, MlParams::new(params, public_vals).to_vec()?))
  }

  fn verify_ml_proof(
    &self,
    args: CliArgs,
    params_reader: BufReader<File>,
    proof: &[u8],
  ) -> circuit_cli::Result<bool> {
    let circuit = args.gen_circuit();
    let params = MlParams::from_reader(params_reader)?;

    let vk = keygen_vk(&params.params, &circuit)
      .map_err(|e| circuit_cli::Error::CliLogicError(format!("keygen vk failed: {}", e)))?;

    let strategy = SingleStrategy::new(&params.params);
    let mut transcript_read = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let ok = verify_proof::<
      KZGCommitmentScheme<Bn256>,
      VerifierSHPLONK<'_, Bn256>,
      Challenge255<G1Affine>,
      Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
      halo2_proofs::poly::kzg::strategy::SingleStrategy<'_, Bn256>,
    >(
      &params.params,
      &vk,
      strategy,
      &[&[&params.public_vals]],
      &mut transcript_read,
    )
    .is_ok();
    Ok(ok)
  }
}

impl MlParams {
  pub fn new(params: ParamsKZG<Bn256>, public_vals: Vec<Fr>) -> Self {
    Self {
      params,
      public_vals,
    }
  }

  pub fn from_reader(mut reader: BufReader<File>) -> circuit_cli::Result<Self> {
    let bin_buf = {
      let mut buf = Vec::new();
      reader.read_to_end(&mut buf)?;
      buf
    };

    let raw: MlParamsSerde = bincode::deserialize(&bin_buf)
      .map_err(|e| circuit_cli::Error::CliLogicError(format!("deserialize params error: {e}")))?;

    let params = Params::read(&mut raw.params.as_slice())?;
    let mut public_vals = Vec::new();
    for i in 0..raw.public_vals.len() / 32 {
      let mut buf = [0u8; 32];
      buf.copy_from_slice(&raw.public_vals[i * 32..(i + 1) * 32]);
      public_vals.push(Fr::from_bytes(&buf).unwrap());
    }
    Ok(Self {
      params,
      public_vals,
    })
  }

  pub fn to_vec(&self) -> circuit_cli::Result<Vec<u8>> {
    let mut params = Vec::new();
    self.params.write(&mut params)?;

    let mut public_vals = Vec::new();
    for val in &self.public_vals {
      public_vals.extend_from_slice(&val.to_bytes());
    }

    Ok(
      bincode::serialize(&MlParamsSerde {
        params,
        public_vals,
      })
      .map_err(|e| circuit_cli::Error::CliLogicError(format!("serialize params error: {e}")))?,
    )
  }
}
