## Background

This POC is inspired by James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) shared at BlackHat USA 2022 titled “[*Taking Kerberos To The Next Level*](https://i.blackhat.com/USA-22/Wednesday/US-22-Forshaw-Taking-Kerberos-To-The-Next-Level.pdf) ” topic, he shared a Demo of abusing Kerberos tickets to achieve UAC bypass. By adding a `KERB-AD-RESTRICTION-ENTRY` to the service ticket, but filling in a fake MachineID, we can easily bypass UAC and gain SYSTEM privileges by accessing the SCM to create a system service. James Forshaw explained the rationale behind this in a blog post called "[*Bypassing UAC in the most Complex Way Possible!*](https://www.tiraniddo.dev/2022/03/bypassing-uac-in-most-complex-way.html)", which got me very interested. Although he didn't provide the full exploit code, I built a POC based on [Rubeus](https://github.com/GhostPack/Rubeus#tgtdeleg). As a C# toolset for raw Kerberos interaction and ticket abuse, Rubeus provides an easy interface that allows us to easily initiate Kerberos requests and manipulate Kerberos tickets.

You can see related articles about KRBUACBypass in my blog "[*Revisiting a UAC Bypass By Abusing Kerberos Tickets*](https://whoamianony.top/posts/revisiting-a-uac-bypass-by-abusing-kerberos-tickets/)", including the background principle and how it is implemented. As said in the article, this article was inspired by @tiraniddo's "Taking Kerberos To The Next Level" (I would not have done it without his sharing) and I just implemented it as a tool before I graduated from college.

### Tgtdeleg Trick

We cannot manually generate a TGT as we do not have and do not have access to the current user's credentials. However, Benjamin Delpy ([@gentilkiwi](https://github.com/gentilkiwi)) in his [Kekeo](https://github.com/gentilkiwi/kekeo/blob/4fbb44ec54ff093ae0fbe4471de19681a8e71a86/kekeo/modules/kuhl_m_tgt.c#L189) A trick (tgtdeleg) was added that allows you to abuse unconstrained delegation to obtain a local TGT with a session key.

Tgtdeleg abuses the Kerberos GSS-API to obtain available TGTs for the current user without obtaining elevated privileges on the host. This method uses the `AcquireCredentialsHandle` function to obtain the Kerberos security credentials handle for the current user, and calls the `InitializeSecurityContext` function for `HOST/DC.domain.com` using the `ISC_REQ_DELEGATE` flag and the target SPN to prepare the pseudo-delegation context to send to the domain controller. This causes the KRB_AP-REQ in the GSS-API output to include the KRB_CRED in the Authenticator Checksum. The service ticket's session key is then extracted from the local Kerberos cache and used to decrypt the KRB_CRED in the Authenticator to obtain a usable TGT. The Rubeus toolset also incorporates this technique. For details, please refer to “[*Rubeus – Now With More Kekeo*](https://blog.harmj0y.net/redteaming/rubeus-now-with-more-kekeo/#tgtdeleg)”.

With this TGT, we can generate our own service ticket, and the feasible operation process is as follows:

1. Use the Tgtdeleg trick to get the user's TGT.
2. Use the TGT to request the KDC to generate a new service ticket for the local computer. Add a `KERB-AD-RESTRICTION-ENTRY`, but fill in a fake MachineID.
3. Submit the service ticket into the cache.

## Krbscm

Once you have a service ticket, you can use Kerberos authentication to access Service Control Manager (SCM) Named Pipes or TCP via HOST/HOSTNAME or RPC/HOSTNAME SPN. Note that SCM's Win32 API always uses Negotiate authentication. James Forshaw created a simple POC: [SCMUACBypass.cpp](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82), through the two APIs HOOK AcquireCredentialsHandle and InitializeSecurityContextW, the name of the authentication package called by SCM (pszPack age ) to Kerberos to enable the SCM to use Kerberos when authenticating locally.

For more details please read:
- For EN-US: https://whoamianony.top/posts/revisiting-a-uac-bypass-by-abusing-kerberos-tickets/
- For ZH-CN: https://paper.seebug.org/3003/

## Let’s see it in action

Now let's take a look at the running effect, as shown in the figure below. First request a ticket for the HOST service of the current server through the asktgs function, and then create a system service through krbscm to gain the SYSTEM privilege.

```console
KRBUACBypass.exe asktgs
KRBUACBypass.exe krbscm
```

![Animation](/images/Animation.gif)
