from avclass import *
from operator import itemgetter
import os
from os.path import basename, splitext, join, exists
import sys
import json
import traceback

class Labeler(object):

    def __init__(self, av_labels, hashtype='sha256', pup=False, family=False,
                 detector=None, gt_dict=None, eval=False, out_dir="./"):
        self.hashtype = hashtype
        hlen = HASH_TYPE_MAP[self.hashtype]
        if hlen is None:
            raise Exception("Invalid hashtype provided: {}".format(self.hashtype))
        self.gt_dict = {} if gt_dict is None else gt_dict
        self.eval = True
        self.av_labels = av_labels
        self.pup = pup
        self.family = family
        self.detector = detector
        
        # Initialize state
        self.processed = 0
        self.empty = 0
        self.singletons = 0
        self.first_token_dict = {}
        self.fam_stats = {}
        if exists(out_dir):
            self.out_dir = out_dir
        else:
            raise Exception("'{}' does not exist: out_dir must exist if specified".format(out_dir))

    def process_sample(self, sample_info):
        self.processed += 1
        # Sample's name is selected hash type (md5 by default)
        name = getattr(sample_info, self.hashtype)

        # Get distinct tokens from AV labels
        tokens = self.av_labels.get_family_ranking(sample_info).items()

        # If alias detection, populate maps
        if self.detector is not None:
            self.detector.detect_aliases(tokens)
            self.detector.detect_generics(tokens)

        # Top candidate is most likely family name
        if tokens:
            family = tokens[0][0]
            is_singleton = False
        else:
            family = "SINGLETON:" + name
            is_singleton = True
            self.singletons += 1

        # Check if sample is PUP, if requested
        if self.pup:
            is_pup = self.av_labels.is_pup(sample_info.labels)
            if is_pup:
                is_pup_str = "\t1"
            else:
                is_pup_str = "\t0"
        else:
            is_pup = None
            is_pup_str =  ""

        # Build family map for precision, recall, computation
        self.first_token_dict[name] = family

        # Get ground truth family, if available
        if len(self.gt_dict) == 0:
            gt_family = None
        else:
            gt_family = self.gt_dict[name] if name in self.gt_dict else None

        # Store family stats (if required)
        if self.family:
            if is_singleton:
                ff = 'SINGLETONS'
            else:
                ff = family
            try:
                numAll, numMal, numPup = self.fam_stats[ff]
            except KeyError:
                numAll = 0
                numMal = 0
                numPup = 0

            numAll += 1
            if self.pup:
                if is_pup:
                    numPup += 1
                else:
                    numMal += 1
            self.fam_stats[ff] = (numAll, numMal, numPup)
        return LabeledSample._make(sample_info + (family, tokens, gt_family, is_pup,))

    def process_files(self, ifile_l):
        # Process each input file
        for ifile in ifile_l:
            # Open file
            with open(ifile, "r") as fd:

                # Debug info, file processed
                #sys.stderr.write('[-] Processing input file %s\n' % ifile)
                sys.stderr.write("[-] Processing input file {}\n".format(ifile))

                # Process all lines in file
                for line in fd:

                    # If blank line, skip
                    if line == '\n':
                        continue

                    # Debug info
                    if self.processed % 100 == 0:
                        sys.stderr.write("\r[-] {:d} JSON read".format(self.processed))
                        sys.stderr.flush()

                    # Read JSON line and extract sample info (i.e., hashes and labels)
                    data = json.loads(line)
                    sample_info = self.av_labels.get_sample_info(data)
                    # If the VT report has no AV labels, continue
                    if sample_info is None or sample_info.labels is None:
                        self.processed += 1
                        self.empty +=1
                        continue

                    try:
                        yield self.process_sample(sample_info)
                    except:
                        traceback.print_exc(file=sys.stderr)
                        continue

                # Debug info
                sys.stderr.write("\r[-] {:d} JSON read".format(self.processed))
                sys.stderr.flush()
                sys.stderr.write('\n')

    def print_statistics(self, out_prefix):
        # Print statistics
        sys.stderr.write(
                "[-] Samples: {:d} NoLabels: {:d} Singletons: {:d} "
                "GroundTruth: {:d}\n".format(
                    self.processed, self.empty, self.singletons, len(self.gt_dict)))

        # If ground truth, print precision, recall, and F1-measure
        if len(self.gt_dict) > 0 and self.eval:
            precision, recall, fmeasure = eval_precision_recall_fmeasure(self.gt_dict,
                                                                         self.first_token_dict)
            sys.stderr.write("Precision: {:.2f}\tRecall: {:.2f}\tF1-Measure: {:.2f}\n".format(
                              precision, recall, fmeasure))

        if self.detector is not None:
            self.detector.write_generic_map(join(self.out_dir, out_prefix + '.gen'))
            self.detector.write_alias_map(join(self.out_dir, out_prefix + '.alias'))

        # If family statistics, output to file
        if self.family:
            self.write_family_data(join(self.out_dir, out_prefix + '.families'))

    def write_family_data(self, path):
        try:
            with open(path, "w+") as fam_fd:
                # Output header line
                if self.pup:
                    fam_fd.write("# Family\tTotal\tMalware\tPUP\tFamType\n")
                else:
                    fam_fd.write("# Family\tTotal\n")
                # Sort map
                sorted_pairs = sorted(self.fam_stats.items(), key=itemgetter(1),
                                      reverse=True)
                # Print map contents
                for (f,fstat) in sorted_pairs:
                    if self.pup:
                        if fstat[1] > fstat[2]:
                            famType = "malware"
                        else:
                            famType = "pup"
                        #fam_fd.write("%s\t%d\t%d\t%d\t%s\n" % (f, fstat[0], fstat[1],
                        fam_fd.write("{}\t{:d}\t{:d}\t{:d}\t{}\n".format(
                            f, fstat[0], fstat[1], fstat[2], famType))
                    else:
                        #fam_fd.write("%s\t%d\n" % (f, fstat[0]))
                        fam_fd.write("{}\t{:d}\n".format(f, fstat[0]))
            sys.stderr.write("[-] Family data in {}\n".format(path))
        except:
            sys.stderr.write("[-] Error writing family data to {}\n".format(path))
            traceback.print_exc(file=sys.stderr)