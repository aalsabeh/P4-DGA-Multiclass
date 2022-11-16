# Dataset description:

  DGA-based malware PCAPs:
  
  The dataset contains the Packet Captures (PCAP) of DGA-based malware samples from different DGA families. The malware samples were executed in an isolated environment for at least 10 minutes (most malware samples were executed for 30 minutes). The PCAPs might contain malicious payload and might be flagged by the antivirus, so please be careful. The PCAPs are in a password-protected compressed file and the password is "infected".
  
  PCAPs in DGA_PCAPS1.7z and DGA_PCAPS1.7z are obtained from DGA-based malware samples collected from VirusTotal (majoriy), VirusShare, and Traige. The PCAPs' names follow the convetion "malwareHash_triageID.pcap", where malwareHash is the hash of the malware sample corresponding to the PCAP file, and triageID and the Triage ID where the sample has been executed. Triage is an online sandbox, if you want to look up more information regarding the Triage analysis of the sample, you can simply visit the link: https://tria.ge/<triageID>.
  
  PCAPs in Malpedia_DGA_pcaps.7z are obtained from DGA-based malware samples collected from Malpedia. There are other PCAPs that I couldn't upload here due to their large size, if you are interested, please email me at: aalsabeh@email.sc.edu
