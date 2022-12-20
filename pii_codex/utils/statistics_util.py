import statistics

import numpy as np


def get_population_standard_deviation(values) -> float:
    return statistics.pstdev(values)


def get_population_variance(values) -> float:
    return statistics.pvariance(values)


def get_standard_deviation(values, collection_type: str) -> float:
    if collection_type.lower() != "sample" and collection_type.lower() != "population":
        raise Exception("Invalid collection type. Must be 'SAMPLE' or 'POPULATION'.")

    return (
        statistics.stdev(values)
        if collection_type.lower() == "sample"
        else get_population_standard_deviation(values)
    )


def get_variance(values, collection_type: str) -> float:
    if collection_type.lower() != "sample" and collection_type.lower() != "population":
        raise Exception("Invalid collection type. Must be 'SAMPLE' or 'POPULATION'.")

    return (
        statistics.variance(values)
        if collection_type.lower() == "sample"
        else get_population_variance(values)
    )


def get_mean(values) -> float:
    return statistics.mean(values)


def get_median(values) -> float:
    return statistics.median(values)


def get_mode(values):
    return statistics.mode(values)


def get_sum(values):
    return np.sum(values)
