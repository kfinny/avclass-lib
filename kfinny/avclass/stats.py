import csv


class FamilyStats(object):

    def __init__(self):
        self.families = {}

    def update(self, family, is_pup):
        if family:
            if family.startswith("SINGLETONS:"):
                ff = 'SINGLETONS'
            else:
                ff = family
            if ff not in self.families:
                self.families[ff] = [0, 0, 0]
            counts = self.families[ff]
            counts[0] += 1
            if is_pup:
                counts[2] += 1
            else:
                counts[1] += 1

    def write_family_data(self, path, dialect=csv.excel_tab):
        with open(path, "w") as fd:
            writer = csv.writer(fd, dialect=dialect)
            writer.writerow(["Family", "Total", "Malware", "PUP", "Type"])
            for family, counts in sorted(self.families.items(), key=lambda v: v[1], reverse=True):
                writer.writerow([family]+counts+["malware" if counts[1] > counts[2] else "pup"])


def tp_fp_fn(correct_set, guess_set):
    """
    INPUT: dictionary with the elements in the cluster from the ground truth
    (CORRECT_SET) and dictionary with the elements from the estimated cluster
    (ESTIMATED_SET).

    OUTPUT: number of True Positives (elements in both clusters), False
    Positives (elements only in the ESTIMATED_SET), False Negatives (elements
    only in the CORRECT_SET).
    """
    tp = 0
    fp = 0
    fn = 0
    for elem in guess_set:
        # True Positives (elements in both clusters)
        if elem in correct_set:
            tp += 1
        else:
            # False Positives (elements only in the "estimated cluster")
            fp += 1
    for elem in correct_set:
        if elem not in guess_set:
            # False Negatives (elements only in the "correct cluster")
            fn += 1
    return tp, fp, fn


def eval_precision_recall_fmeasure(ground_truth, estimated):
    """
    INPUT: dictionary with the mapping "element:cluster_id" for both the ground
    truth and the ESTIMATED_DICT clustering.

    OUTPUT: average values of Precision, Recall and F-Measure.
    :param ground_truth: mapping of name (i.e. hashval) to family
    :param estimated: mapping of name to family determined by AvClass
    :return: 3-tuple of precision, recall and f-measure
    """
    # eval: precision, recall, f-measure
    tmp_precision = 0
    tmp_recall = 0

    # build reverse dictionary of ESTIMATED_DICT
    rev_est_dict = {}
    for k, v in estimated.items():
        if v not in rev_est_dict:
            rev_est_dict[v] = set([k])
        else:
            rev_est_dict[v].add(k)

    # build reverse dictionary of GROUNDTRUTH_DICT
    gt_rev_dict = {}
    for k, v in ground_truth.items():
        if v not in gt_rev_dict:
            gt_rev_dict[v] = set([k])
        else:
            gt_rev_dict[v].add(k)

    # For each element
    for element in estimated:

        # Get elements in the same cluster (for "ESTIMATED_DICT cluster")
        guess_cluster_id = estimated[element]

        # Get the list of elements in the same cluster ("correct cluster")
        correct_cluster_id = ground_truth[element]

        # Calculate TP, FP, FN
        tp, fp, fn = tp_fp_fn(gt_rev_dict[correct_cluster_id],
                              rev_est_dict[guess_cluster_id])

        # tmp_precision
        p = 1.0 * tp / (tp + fp)
        tmp_precision += p
        # tmp_recall
        r = 1.0 * tp / (tp + fn)
        tmp_recall += r
    precision = tmp_precision / len(estimated)
    recall = tmp_recall / len(estimated)
    f_measure = (2 * precision * recall) / (precision + recall)
    return precision, recall, f_measure
