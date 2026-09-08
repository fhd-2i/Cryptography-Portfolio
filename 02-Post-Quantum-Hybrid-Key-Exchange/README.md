\# Post-Quantum Hybrid Key Exchange



A practical cryptography project demonstrating a hybrid key exchange that combines classical X25519 with post-quantum ML-KEM-768.



The resulting shared secret material is combined using HKDF-SHA256 to derive a 256-bit AES key, which is then used with AES-256-GCM for authenticated encryption.



\## Overview



This project demonstrates a hybrid cryptographic design using both classical and post-quantum key establishment.



The sender uses:



\- X25519 for classical elliptic-curve Diffie-Hellman key agreement

\- ML-KEM-768 for post-quantum key encapsulation

\- HKDF-SHA256 for hybrid key derivation

\- AES-256-GCM for authenticated encryption



Both the classical and post-quantum shared secrets are combined before deriving the final AES-256 key.



\## Architecture



```text

Recipient X25519 Public Key

&#x20;           |

&#x20;           v

Sender Ephemeral X25519

&#x20;           |

&#x20;           v

X25519 Shared Secret

&#x20;           |

&#x20;           |

&#x20;           +-------------------+

&#x20;                               |

ML-KEM-768 Encapsulation        |

&#x20;           |                   |

&#x20;           v                   |

ML-KEM Shared Secret            |

&#x20;           |                   |

&#x20;           +-------------------+

&#x20;                               |

&#x20;                               v

&#x20;                         HKDF-SHA256

&#x20;                               |

&#x20;                               v

&#x20;                        256-bit AES Key

&#x20;                               |

&#x20;                               v

&#x20;                         AES-256-GCM

&#x20;                               |

&#x20;                               v

&#x20;                      Encrypted Message

