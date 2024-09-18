import { fromByteArray, toByteArray } from "base64-js";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";
import { D1QB, DefaultObject } from "workers-qb";

const rpName = "TestWebAuthn";
const rpID = "localhost";
const origin = `http://localhost:8787`;

interface Passkey {
  id: string;
  credentialId: string;
  publicKey: Uint8Array;
  userName: string;
  counter: number;
}

interface DBPasskey extends DefaultObject {
  id: string;
  credential_id: string;
  public_key: string;
  username: string;
  counter: number;
  updated_at: string;
  created_at: string;
}

interface Env {
  KV: KVNamespace;
  DB: D1Database;
}

const passkeyToDBPasskey = (
  passkey: Passkey
): Omit<DBPasskey, "update_at" | "created_at"> => {
  return {
    id: passkey.id,
    credential_id: passkey.credentialId,
    public_key: fromByteArray(passkey.publicKey),
    username: passkey.userName,
    counter: passkey.counter,
  };
};

const DBPasskeyToPassKey = async (d1Passkey: DBPasskey): Promise<Passkey> => {
  return {
    id: d1Passkey.id,
    credentialId: d1Passkey.credential_id,
    publicKey: toByteArray(d1Passkey.public_key),
    userName: d1Passkey.username,
    counter: d1Passkey.counter,
  };
};

// チャレンジを KV に保存
const storeChallenge = async (
  userName: string,
  challenge: string,
  { KV }: Env
) => {
  await KV.put(`challenge/${userName}`, challenge);
};

// チャレンジを KV から取得
const getChallenge = async (userName: string, { KV }: Env) => {
  const challenge = await KV.get(`challenge/${userName}`);
  if (!challenge) {
    throw new Error("No challenge exists.");
  }
  return challenge;
};

// パスキーを DB に保存
const insertPassKey = async (passkey: Passkey, { DB }: Env) => {
  const qb = new D1QB(DB);
  await qb
    .insert<DBPasskey>({
      tableName: "passkey",
      data: passkeyToDBPasskey(passkey),
    })
    .execute();
};

// DB 中のパスキーを更新
const updatePasskey = async (passkey: Passkey, { DB }: Env) => {
  const qb = new D1QB(DB);
  await qb
    .update<DBPasskey>({
      tableName: "passkey",
      data: passkeyToDBPasskey(passkey) as any,
      where: {
        conditions: "id = ?1",
        params: [passkey.userName],
      },
    })
    .execute();
};

// ユーザ名に紐づいたパスキーをすべて取得
const getUserPasskeys = async (userName: string, { DB }: Env) => {
  const qb = new D1QB(DB);
  const result = await qb
    .fetchAll<DBPasskey>({
      tableName: "passkey",
      fields: "*",
      where: {
        conditions: "username = ?1",
        params: [userName],
      },
    })
    .execute();

  const values = result.results ?? [];
  const passkeys: Passkey[] = [];
  for (const value of values) {
    passkeys.push(await DBPasskeyToPassKey(value));
  }
  return passkeys;
};

export const getRegistrationOptions = async (userName: string, env: Env) => {
  const passkeys = await getUserPasskeys(userName, env);
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName,
    excludeCredentials: passkeys.map((passkey) => ({
      id: passkey.credentialId,
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });
  await storeChallenge(userName, options.challenge, env);
  return options;
};

export const verifyRegistration = async (
  userName: string,
  body: RegistrationResponseJSON,
  env: Env
) => {
  const challenge = await getChallenge(userName, env);
  const verification = await verifyRegistrationResponse({
    response: body,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  });
  if (!verification.verified) {
    throw new Error("Not verified.");
  }
  const info = verification.registrationInfo!;
  const passkey: Passkey = {
    userName,
    id: `${userName}/${info.aaguid}`,
    credentialId: info.credentialID,
    publicKey: info.credentialPublicKey,
    counter: info.counter,
  };
  await insertPassKey(passkey, env);
};

export const getAuthenticationOptions = async (userName: string, env: Env) => {
  const userPasskeys = await getUserPasskeys(userName, env);
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: userPasskeys.map((passkey) => ({
      id: passkey.credentialId,
    })),
  });
  await storeChallenge(userName, options.challenge, env);
  return options;
};

export const verifyAuthentication = async (
  userName: string,
  body: AuthenticationResponseJSON,
  env: Env
) => {
  const challenge = await getChallenge(userName, env);
  const allPasskeys = await getUserPasskeys(userName, env);
  const passkey = allPasskeys.find(
    ({ credentialId }) => credentialId === body.id
  );
  if (!passkey) {
    throw new Error(`No passkey exists.`);
  }
  const verification = await verifyAuthenticationResponse({
    response: body,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: {
      credentialID: passkey.credentialId,
      credentialPublicKey: passkey.publicKey,
      counter: passkey.counter,
    },
  });

  if (verification.verified) {
    const newPasskey = structuredClone(passkey);
    passkey.counter = verification.authenticationInfo.newCounter;
    await updatePasskey(newPasskey, env);
  }
  return verification.verified;
};
