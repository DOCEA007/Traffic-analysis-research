# Traffic Capturer for Windows Updates

## Automation:
Known domain, known port, known timeframe ( because we send the request or know when the request will be sent). 

## Utilities:
1. **Domain**: fe2cr.update.microsoft.com
2. **Port**: 443
3. **Command to test API**:
```bash
cd "C:\Program Files\Windows Defender"
.\MpCmdRun.exe -SignatureUpdate -ForceUpdate
```

This is a program that checks for the **signature** of the windows updates **version**.
```bash
C:\Program Files\Windows Defender>.\MpCmdRun.exe -SignatureUpdate -ForceUpdate
Signature update started . . .
Service Version: 4.18.25110.5
Engine Version: 1.1.25110.1
AntiSpyware Signature Version: 1.443.173.0
AntiVirus Signature Version: 1.443.173.0
...
```
4.

## Detection Script

#### Link to our script: [main](main.py)

#### Steps for script:

1. **DNS Resolver**  
This checks for the latest ip of *fe2cr.update.microsoft.com* (**the windows update api**), but the ip is dynamic and changes overtime.

2. **Analyzing PIDs**  
We also know that every single file that runs end in **.exe** so we cannot miss the application aswell as its path.

3. **Capturing the traffic**  
With the *IP* and *Application* **known** its enough to filter the traffic and gather information of the updates that are being done.

4. **Saving the output**  
All the traffic can be saved in a normal .txt file or a .csv for **analysis**, if needed.
#### Note: The script doesn't need administrator permissions to run.

### If needed we can decrypt the traffic in order to verify the updates for **research purposes**.

## Possibilties of decryption
-> [Schannel](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview)

**Schannel** is a certified encryption method made by **microsoft** for windows capabilities.  
The Security Support Provider Interface (SSPI) is an **API** used by Windows systems to perform security-related functions including authentication. The **SSPI** functions as a common interface to several **SSPs**, including the **Schannel SSP**.  
The Schannel authentication protocol suite provides several protocols that all use a **client/server model**. The following protocols are based on public key cryptography:  
1. **TLS** versions 1.0, 1.1, 1.2, and 1.3  
2. **SSL** versions 2.0 and 3.0  
3. Datagram Transport Layer Security (**DTLS**) versions 1.0 and 1.2  
4. Private Communications Transport (**PCT**)

#### However we don't necessarly need to decrypt the traffic in order to check for the updates being done, because these requests are done autonomous by Windows Defender/Updates.

### Advantages

1. The **knowledge** of being able to know that if the endpoint has the **lastest updates** and maintains overall a **continously and stable trust of protection**.
2. The script does **not** need administrator permissions to run.
