from .avclass import AvLabels, LabeledSample
from .stats import FamilyStats, eval_precision_recall_fmeasure
from .util import pick_hash
import csv
from hashlib import sha256
from operator import itemgetter
from six import iteritems
import json
import traceback
import logging

__all__ = ("Labeler", "Detector", "GroundTruth")


class Labeler(object):

    def __init__(self, av_labels=None, gt_path=None):
        self.av_labels = AvLabels() if av_labels is None else av_labels
        self.ground_truth = GroundTruth()
        if gt_path is not None:
            try:
                self.ground_truth.load_ground_truth(gt_path)
            except IOError:
                logging.warning("Could not load ground truth file at {}".format(gt_path))
        self.detector = Detector()
        self.pup = True

        # Initialize state
        self.processed = 0
        self.empty = 0
        self.singletons = 0
        self.fam_stats = FamilyStats()

    def toggle_pup(self):
        self.pup = not self.pup
        return self.pup

    def toggle_generic_detection(self):
        self.detector.generic = not self.detector.generic
        return self.detector.generic

    def toggle_alias_detection(self):
        self.detector.alias = not self.detector.alias
        return self.detector.alias

    def process_sample(self, sample_info):
        self.processed += 1
        if sample_info is None or sample_info.labels is None:
            self.empty += 1
            return None
        # Sample's hashval is selected hash type (sha256 by default)
        hashval = pick_hash(sample_info)

        # Get distinct tokens from AV labels
        tokens = list(self.av_labels.get_family_ranking(sample_info).items())
        # Top candidate is most likely family
        if tokens:
            family = tokens[0][0]
        else:
            family = "SINGLETON:" + hashval
            self.singletons += 1

        # Check if sample is PUP, if requested
        is_pup = self.av_labels.is_pup(sample_info.labels) if self.pup else None

        # Get ground truth family, if available
        gt_family, hashval = self.ground_truth.retrieve(*sample_info)
        if hashval is not None:
            # Build family map for precision, recall, computation
            # noinspection PyTypeChecker
            self.ground_truth.label(hashval, family)

        # If alias detection and/or generic detection, populate maps
        self.detector.update(gt_family, tokens)

        # Store family stats (if required)
        self.fam_stats.update(gt_family if gt_family is not None else family, is_pup)
        return LabeledSample(*(sample_info + (family, tokens, gt_family, is_pup,)))

    def process_object(self, obj):
        sample_info = self.av_labels.get_sample_info(obj)
        return self.process_sample(sample_info)

    def process_json(self, json_data):
        sample_info = self.av_labels.get_sample_info(json_data)
        try:
            return self.process_sample(sample_info)
        except:
            logging.warning(traceback.format_exc())
            return None

    def process_files(self, file_list, line_delimited=False):
        # Process each input file
        for path in file_list:
            with open(path, "r") as fd:
                # Debug info, file processed
                logging.info("[-] Processing input file {}".format(path))

                if line_delimited:
                    # Process all lines in file
                    for line in fd:
                        # If blank line, skip
                        if line == '\n':
                            continue

                        # Debug info
                        if self.processed % 100 == 0:
                            logging.debug("[-] {:d} JSON read".format(self.processed))

                        yield self.process_json(json.loads(line))
                else:
                    yield self.process_json(json.load(fd))

        logging.debug("[-] {:d} JSON read".format(self.processed))

    def log_statistics(self):
        # Print statistics
        logging.info("[-] Samples: {:d} NoLabels: {:d} Singletons: {:d}".format(
            self.processed, self.empty, self.singletons))

        # If ground truth, print precision, recall, and F1-measure
        self.ground_truth.log_statistics()

    def __str__(self):
        return "yeah, sure"


class GroundTruth(object):

    def __init__(self):
        self.mapped = {}
        self.labeled = {}

    def load_ground_truth(self, gt_path, dialect=csv.excel_tab, has_header=False):
        with open(gt_path, 'r') as gt_fd:
            reader = csv.reader(gt_fd, dialect=dialect)
            if has_header:
                reader.next()
            for row in reader:
                self.update(*row)

    def update(self, hashval, family):
        hv = hashval.strip().lower()
        self.mapped[sha256(hv).hexdigest()] = (family, hashval, )

    def label(self, hashval, family):
        """Applies family label to labeled dict if hashval is in ground truth dict

        :param hashval: str
        :param family: str
        """
        hv = sha256(hashval.strip().lower()).hexdigest()
        if hv in self.mapped:
            self.labeled[hv] = (family, hashval, )

    def retrieve(self, *hashvals):
        if len(self.mapped) == 0:
            return None, None
        hv = self.contains(*hashvals)
        if hv is not None:
            return self.mapped[hv]
        return None, None

    def contains(self, *hashvals):
        for hv in [sha256(h.strip().lower()).hexdigest() for h in hashvals if isinstance(h, str)]:
            if hv in self.mapped:
                return hv
        return None

    def log_statistics(self):
        if len(self.mapped) > 0 and set(self.mapped.keys()) == set(self.labeled.keys()):
            gt = dict([(hv, family[0]) for hv, family in self.mapped.items()])
            lb = dict([(hv, family[0]) for hv, family in self.labeled.items()])
            precision, recall, fmeasure = eval_precision_recall_fmeasure(gt, lb)
            logging.info("Precision: {:.2f}\tRecall: {:.2f}\tF1-Measure: {:.2f}".format(
                              precision, recall, fmeasure))
        else:
            logging.info("[-] labeled and mapped dictionaries are not equivalent, will not calculate precision, recall "
                         "and F1-measure")


class Detector(object):

    def __init__(self):
        self.alias = True
        self.generic = True
        self.generic_threshold = 8
        self.token_count_map = {}
        self.pair_count_map = {}
        self.token_family_map = {}

    def update(self, gt_family, tokens):
        """Convenience method that calls detect_aliases and detect_generics

        :param gt_family:
        :param tokens:
        """
        self.detect_aliases(tokens)
        self.detect_generics(gt_family, tokens)

    def detect_aliases(self, tokens):
        """List of 2-tuple (token, count) where count is occurrence across labels for given sample

        :param tokens:
        :return:
        """
        if not self.alias:
            return

        def inc_map_count(_map, key):
            _map[key] = _map.get(key, 0) + 1

        seen_tokens = []
        for tok in sorted(set([t for t, c in tokens])):
            inc_map_count(self.token_count_map, tok)
            for prev_tok in sorted(seen_tokens):
                pair = (prev_tok, tok)
                inc_map_count(self.pair_count_map, pair)
            seen_tokens.append(tok)

    def detect_generics(self, gt_family, tokens):
        """List of 2-tuple (token, count) where count is occurrence across labels for given sample

        :param gt_family:
        :param tokens:
        :return:
        """
        if not self.generic or gt_family is None:
            return
        for tok, count in tokens:
            if tok not in self.token_family_map:
                self.token_family_map[tok] = set()
            self.token_family_map[tok].add(gt_family)

    def write_alias_map(self, path):
        if not self.alias:
            return
        try:
            sorted_pairs = sorted(
                self.pair_count_map.items(), key=itemgetter(1), reverse=True)
            with open(path, 'w+') as alias_fd:
                # Sort token pairs by number of times they appear together
                writer = csv.writer(alias_fd, dialect=csv.excel_tab)
                # Output header line
                writer.writerow(["t1", "t2", "|t1|", "|t2|", "|t1^t2|", "|t1^t2|/|t1|"])
                # Compute token pair statistic and output to alias file
                for (t1, t2), c in sorted_pairs:
                    n1 = self.token_count_map[t1]
                    n2 = self.token_count_map[t2]
                    if n1 < n2:
                        x = t1
                        y = t2
                        xn = n1
                        yn = n2
                    else:
                        x = t2
                        y = t1
                        xn = n2
                        yn = n1
                    f = float(c) / float(xn)
                    writer.writerow([x, y, str(xn), str(yn), str(c), "{:.2f}".format(f)])
            logging.info("[-] Alias data in {}".format(path))
        except IOError:
            logging.warning("[-] Error writing alias data to {}".format(path))

    def write_generic_map(self, path):
        if not self.generic:
            return
        try:
            with open(path, 'w+') as gen_fd:
                # Output header line
                gen_fd.write("Token\t#Families\n")
                sorted_pairs = sorted(self.token_family_map.items(),
                                      key=lambda x: len(x[1]) if x[1] else 0,
                                      reverse=True)
                for (t, fset) in sorted_pairs:
                    gen_fd.write("{}\t{:d}\n".format(t, len(fset)))
            logging.info("[-] Generic token data in {}".format(path))
        except IOError:
            logging.warning("[-] Error writing generic token data to {}".format(path))
