---
title:
  'pii-codex: a Python library for PII detection, categorization, and severity assessment'
tags:
  - Python
  - PII
  - PII topology
  - risk categories
  - personal identifiable information
authors:
  - name: Eidan J. Rosado
    orcid: 0000-0003-0665-098X
    affiliation: 1
affiliations:
  - name:
      College of Computing and Engineering, Nova Southeastern University, Fort Lauderdale, FL 33314,
      USA
    index: 1
date: 28 Dec 2022
bibliography: paper.bib
---

# Summary

PII-Codex is a collection of extended theoretical, conceptual, and policy works in personal identifiable information (PII) categorization and severity assessment [@schwartz_solove_2011; @milne_pettinico_hajjat_markos_2016], and the integration thereof with PII detection software and API client adapters. It allows researchers to analyze a body of text or a collection thereof and determine whether the PII detected within these texts, if any, are considered identifiable. Furthermore, it allows end-users to determine the severity and associated categorizations of detected PII tokens.

# Challenges

While several open-source PII detection libraries and even more PII detection clients are provided by cloud service providers [@azure_detection_cognitive_skill; @aws_comprehend], the detections often come with an index reference of where the detection is within the text and a confidence score associated with the detection. For those receiving these results, they aren’t provided with a means of understanding how the text is classified as PII, what framework, policy, or convention labels it as such, and just how severe.
# Statement of Need

The knowledge base of identifiable data, its use, and associated policies have shifted drastically over the years. The tech industry has seen many policy changes regarding the tracking of individuals, the usage of data from online profiles, and the right to be forgotten entirely from a service or platform [@gdpr]. Understanding if identifiable data types exist in a dataset can prevent accidental sharing of such data by allowing its detection in the first place and, in the case of this software, present sanitized and publishable results.

# The PII-Codex Package

PII-Codex is a Python package with an intended scope to combine the Information Sensitivity Typology works of Milne et al. [@milne_pettinico_hajjat_markos_2016], categorizations and guidelines from the National Institute of Standards and Technology (NIST) [@mccallister_grance_scarfone_2010], Department of Homeland Security (DHS) [@dhs_2012], and the Health Insurance Portability and Accountability Act (HIPAA) [@hipaa]. It combines these categories to rate the detection on a scale of 1 to 3, labeling it as Non-Identifiable, Semi-Identifiable, or Identifiable as presented by the risk continuum by Schwartz and Solove [@schwartz_solove_2011]. 

Built into the package is an analyzer service that leverages Microsoft’s Presidio library for PII detection and anonymization [@microsoft_presidio] as well as the option to use the built-in detection adapters for Microsoft Presidio, Azure Detection Cognitive Skill [@azure_detection_cognitive_skill], and AWS Comprehend [@aws_comprehend] for pre-existing detections. The output of the adapters are analysis objects with a listing of detections, severities, mean risk scores for each string processed, and summary statistics on the analysis made. The final outputs do not contain the original texts but provide the sanitized or anonymized texts and where to find the detections, should the end-user require this information. In providing this capability, one can prevent the accidental dissemination of private information in downstream research efforts, an issue commonly discussed in cybersecurity research [@moura_serrão_2019; @beigi_liu_2020].

# References