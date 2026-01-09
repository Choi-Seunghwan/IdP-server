#!/usr/bin/env python3

import sys
from pathlib import Path

# 프로젝트 루트를 Python 경로에 추가
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.jwt_keys import generate_rsa_key_pair, save_rsa_key_pair


def main():
    # 키 저장 디렉토리
    keys_dir = project_root / "keys"
    keys_dir.mkdir(exist_ok=True)

    private_key_path = keys_dir / "private_key.pem"
    public_key_path = keys_dir / "public_key.pem"

    # 키가 이미 존재하는지 확인
    if private_key_path.exists() or public_key_path.exists():
        response = input(f"키 파일이 이미 존재합니다. 덮어쓰시겠습니까? (y/N): ")
        if response.lower() != "y":
            print("취소되었습니다.")
            return

    print("RSA 키 쌍 생성 중...")
    private_key, public_key = generate_rsa_key_pair()

    print(f"Private Key 저장: {private_key_path}")
    print(f"Public Key 저장: {public_key_path}")
    save_rsa_key_pair(private_key, public_key, str(private_key_path), str(public_key_path))

    print("\ 키 쌍 생성 완료!")


if __name__ == "__main__":
    main()
