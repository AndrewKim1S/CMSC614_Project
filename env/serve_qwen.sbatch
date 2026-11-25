#!/bin/bash
# Dedicated vLLM server for CMSC614 experiments. Same model and settings as the
# shared server (Qwen3.8-27B, FP8, tensor-parallel over 2 RTX A5000), but the
# endpoint goes to cmsc614/endpoints/<jobid>.txt so it never clobbers another
# project's endpoint file.
#   sbatch env/serve_qwen.sbatch            (submit once per server wanted)
#SBATCH --job-name=cmsc614-qwen
#SBATCH --partition=tron
#SBATCH --account=nexus
#SBATCH --qos=medium
#SBATCH --gres=gpu:rtxa5000:2
#SBATCH --cpus-per-task=6
#SBATCH --mem=64G
#SBATCH --time=06:00:00
#SBATCH --output=/fs/nexus-scratch/%u/cmsc614/CMSC614_Project/logs/serve-%j.log
S=/fs/nexus-scratch/$USER
export HF_HOME=$S/.hf-cache
export CUDA_HOME=$S/venv-vllm/lib/python3.11/site-packages/nvidia/cu13
export PATH=$CUDA_HOME/bin:$S/venv-vllm/bin:$PATH
export VLLM_ATTENTION_BACKEND=TRITON_ATTN VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_DISABLE_FLASHINFER=1
mkdir -p $S/cmsc614/endpoints
# Port from the job id: two servers on one node once both "started" on 8000 (vLLM sets
# SO_REUSEPORT) and the first one got every request.
PORT=$((8000 + SLURM_JOB_ID % 1000))
echo "http://$(hostname):$PORT/v1" > $S/cmsc614/endpoints/$SLURM_JOB_ID.txt
trap 'rm -f $S/cmsc614/endpoints/$SLURM_JOB_ID.txt' EXIT
vllm serve Qwen/Qwen3.8-27B --quantization fp8 --tensor-parallel-size 2 \
    --max-model-len 24576 --gpu-memory-utilization 0.92 --max-num-seqs 24 \
    --port $PORT --host 0.0.0.0
