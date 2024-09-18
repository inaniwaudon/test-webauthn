const register = async () => {
  try {
    const userName = document.getElementById("userName").value;
    const params = new URLSearchParams({ userName: userName });
    const optionsResponse = await fetch(`/attestation/options?${params}`);
    const { options } = await optionsResponse.json();

    const registration = await SimpleWebAuthnBrowser.startRegistration(options);
    const verificationResponse = await fetch("/attestation/result", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ userName, body: registration }),
    });
    const verification = await verificationResponse.json();

    if (verification.verified) {
      alert("登録に成功しました");
    } else {
      alert(`登録に失敗しました: ${verification.error}`);
    }
  } catch (e) {
    alert(`登録に失敗しました: ${e}`);
  }
};

const verify = async () => {
  try {
    const userName = document.getElementById("userName").value;
    const params = new URLSearchParams({ userName: userName });
    const optionsResponse = await fetch(`/assertion/options?${params}`);
    const { options } = await optionsResponse.json();

    const authentication = await SimpleWebAuthnBrowser.startAuthentication(
      options
    );
    const verificationResponse = await fetch("/assertion/result", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ userName, body: authentication }),
    });
    const verification = await verificationResponse.json();

    if (verification.verified) {
      alert("認証に成功しました");
    } else {
      alert(`認証に失敗しました: ${verification.error}`);
    }
  } catch (e) {
    alert(`認証に失敗しました: ${e}`);
  }
};
