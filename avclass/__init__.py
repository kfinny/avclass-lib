import re
import string
import sys
from collections import OrderedDict as OrdDict
from collections import namedtuple
from operator import itemgetter, attrgetter

import traceback


SampleInfo = namedtuple('SampleInfo', 
                        ['md5', 'sha1', 'sha256', 'labels'])

LabeledSample = namedtuple('LabeledSample',
                           ['md5', 'sha1', 'sha256', 'labels', 'family', 'tokens', 'groundtruth','is_pup'])

HASH_TYPE_MAP = {"md5":32, 32:"md5", "sha1":40, 40:"sha1", "sha256":64, 64:"sha256"}
def guess_hash(h):
    '''Given a hash string, guess the hash type based on the string length'''
    try:
        return HASH_TYPE_MAP[len(h)]
    except KeyError:
        pass
    except TypeError:
        pass
    return None

def get_data_file_path(name):
    from os.path import split, join
    return join(split(__file__)[0],"data",name)

def load_ground_truth(gt):
    gt_dict = {}
    detected_len = None
    with open(gt, 'r') as gt_fd:
        for line in gt_fd:
            gt_hash, family = map(str.lower, line.strip().split("\t", 1))
            gt_dict[gt_hash] = family
            hlen = len(gt_hash)
            if detected_len != hlen:
                if detected_len is None:
                    detected_len = hlen
                else:
                    raise Exception("Hash type mismatch detected in ground truth file: " +
                                    "detected is {}, found {} @ {}".format(HASH_TYPE_MAP[detected_len],
                                                                           HASH_TYPE_MAP[hlen],
                                                                           line))
    return (HASH_TYPE_MAP[detected_len], gt_dict)

def tp_fp_fn(CORRECT_SET, GUESS_SET):
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
    for elem in GUESS_SET:
        # True Positives (elements in both clusters)
        if elem in CORRECT_SET:
            tp += 1
        else:
            # False Positives (elements only in the "estimated cluster")
            fp += 1
    for elem in CORRECT_SET:
        if elem not in GUESS_SET:
            # False Negatives (elements only in the "correct cluster")
            fn += 1
    return tp, fp, fn


def eval_precision_recall_fmeasure(GROUNDTRUTH_DICT, ESTIMATED_DICT):
    """
    INPUT: dictionary with the mapping "element:cluster_id" for both the ground
    truth and the ESTIMATED_DICT clustering.

    OUTPUT: average values of Precision, Recall and F-Measure.
    """
    # eval: precision, recall, f-measure
    tmp_precision = 0
    tmp_recall = 0

    # build reverse dictionary of ESTIMATED_DICT
    rev_est_dict = {}
    for k, v in ESTIMATED_DICT.items():
        if v not in rev_est_dict:
            rev_est_dict[v] = set([k])
        else:
            rev_est_dict[v].add(k)

    # build reverse dictionary of GROUNDTRUTH_DICT
    gt_rev_dict = {}
    for k, v in GROUNDTRUTH_DICT.items():
        if v not in gt_rev_dict:
            gt_rev_dict[v] = set([k])
        else:
            gt_rev_dict[v].add(k)

    
    counter, l = 0, len(ESTIMATED_DICT)

    sys.stderr.write('Calculating precision and recall\n')

    # For each element
    for element in ESTIMATED_DICT:
        
        # Print progress
        if counter % 1000 == 0:
            sys.stderr.write('\r%d out of %d' % (counter, l))
            sys.stderr.flush()
        counter += 1

        # Get elements in the same cluster (for "ESTIMATED_DICT cluster")
        guess_cluster_id = ESTIMATED_DICT[element]

        # Get the list of elements in the same cluster ("correct cluster")
        correct_cluster_id = GROUNDTRUTH_DICT[element]

        # Calculate TP, FP, FN
        tp, fp, fn = tp_fp_fn(gt_rev_dict[correct_cluster_id],
                              rev_est_dict[guess_cluster_id])

        # tmp_precision
        p = 1.0*tp/(tp+fp)
        tmp_precision += p
        # tmp_recall
        r = 1.0*tp/(tp+fn)
        tmp_recall += r
    sys.stderr.write('\r%d out of %d' % (counter, l))
    sys.stderr.write('\n')
    precision = 100.0*tmp_precision/len(ESTIMATED_DICT)
    recall = 100.0*tmp_recall/len(ESTIMATED_DICT)
    fmeasure = (2*precision*recall)/(precision+recall)
    return precision, recall, fmeasure

class Detector(object):

    def __init__(self, groundtruth, alias=False, generic=False):
        self.alias = alias
        self.generic = generic
        self.groundtruth = groundtruth
        self.token_count_map = {}
        self.pair_count_map = {}
        self.token_family_map = {}

    def detect_aliases(self, tokens):
        '''List of 2-tuple (token, count) where count is occurrence across labels for given sample'''
        if not self.alias:
            return
        
        def inc_map_count(map, key):
            count = map.get(key, 0)
            map[key] = count + 1

        prev_tokens = set([])
        for entry in tokens:
            curr_tok = entry[0]
            inc_map_count(self.token_count_map, curr_tok)
            for prev_tok in prev_tokens:
                if prev_tok < curr_tok:
                    pair = (prev_tok,curr_tok) 
                else: 
                    pair = (curr_tok,prev_tok)
                inc_map_count(self.pair_count_map, pair)
            prev_tokens.add(curr_tok)

    def detect_generics(self, tokens):
        '''List of 2-tuple (token, count) where count is occurrence across labels for given sample'''
        if not self.generic or len(self.groundtruth) == 0:
            return
        for entry in tokens:
            curr_tok = entry[0]
            family = self.groundtruth[name] if name in self.groundtruth else None
            if family is not None:
                if curr_tok not in self.token_family_map:
                    self.token_family_map = set()
                self.token_family_map[curr_tok].add(family)

    def write_alias_map(self, path):
        if not self.alias:
            return
        try:
            with open(path, 'w+') as alias_fd:
                # Sort token pairs by number of times they appear together
                sorted_pairs = sorted(
                        self.pair_count_map.items(), key=itemgetter(1))
                # Output header line
                alias_fd.write("# t1\tt2\t|t1|\t|t2|\t|t1^t2|\t|t1^t2|/|t1|\n")
                # Compute token pair statistic and output to alias file
                for (t1,t2),c in sorted_pairs:
                    n1 = self.token_count_map[t1]
                    n2 = self.token_count_map[t2]
                    if (n1 < n2):
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
                    #alias_fd.write("%s\t%s\t%d\t%d\t%d\t%0.2f\n" % (
                    alias_fd.write("{}\t{}\t{:d}\t{:d}\t{:d}\t{:.2f}\n".format(
                        x,y,xn,yn,c,f))
            sys.stderr.write("[-] Alias data in {}\n".format(path))
        except:
            sys.stderr.write("[-] Error writing lias data to {}\n".format(path))

    def write_generic_map(self, path):
        if not self.generic:
            return
        try:
            with open(path, 'w+') as gen_fd:
                # Output header line
                gen_fd.write("Token\t#Families\n")
                sorted_pairs = sorted(token_family_map.iteritems(), 
                                      key=lambda x: len(x[1]) if x[1] else 0, 
                                      reverse=True)
                for (t,fset) in sorted_pairs:
                    gen_fd.write("{}\t{:d}\n".format(t, len(fset)))
            sys.stderr.write("[-] Generic token data in {}\n".format(path))
        except:
            sys.stderr.write("[-] Error writing generic token data to {}\n".format(path))


class AvLabels(object):
    '''
    Class to operate on AV labels, 
    such as extracting the most likely family name.
    '''
    def __init__(self, gen_file = None, alias_file = None, av_file = None):

        # Read generic token set from file
        try:
            if gen_file is None:
                gen_file = get_data_file_path("default.generics")
            self.gen_set = self.read_generics(gen_file)
        except:
            #traceback.print_exc(file=sys.stderr)
            self.gen_set = set()

        # Read aliases map from file
        try:
            if alias_file is None:
                alias_file = get_data_file_path("default.aliases")
            self.aliases_map = self.read_aliases(alias_file)
        except:
            #traceback.print_exc(file=sys.stderr)
            self.aliases_map = {}

        # Read AV engine set from file
        self.avs = self.read_avs(av_file) if av_file else None

    @staticmethod
    def read_aliases(alfile):
        '''Read aliases map from given file'''
        if alfile is None:
            return {}
        almap = {}
        with open(alfile, 'r') as fd:
            for line in fd:
                alias, token = line.strip().split()[0:2]
                almap[alias] = token
        return almap

    @staticmethod
    def read_generics(generics_file):
        '''Read generic token set from given file'''
        gen_set = set()
        with open(generics_file) as gen_fd:
            for line in gen_fd:
                if line.startswith('#') or line == '\n':
                    continue
                gen_set.add(line.strip())
        return gen_set

    @staticmethod
    def read_avs(avs_file):
        '''Read AV engine set from given file'''
        with open(avs_file) as fd:
            avs = set(map(str.strip, fd.readlines()))
        return avs

    @staticmethod
    def get_sample_info(data):
        '''Parse and extract sample information from JSON data
           Returns a SampleInfo named tuple: md5, sha1, sha256, label_pairs 
           
           This method has been improved to handle multiple JSON data formats
           Recognized formats include:
           - VT File Report
           - VT Notification
           - AVClass simplified JSON
        '''
        try:
            if "response_code" in data:
                # VT file report
                strip_unprintable = lambda x: x in string.printable
                clean = lambda x: filter(strip_unprintable, x).strip().encode('utf-8')

                if data["response_code"] == 0:
                    return None
                label_pairs = [(av,clean(result["result"])) for av,result in data["scans"].items() if result["result"] is not None]
            elif "ruleset_name" in data:
                # VT notification
                strip_unprintable = lambda x: x in string.printable
                clean = lambda x: filter(strip_unprintable, x).strip().encode('utf-8')

                label_pairs = [(av,clean(result)) for av,result in data["scans"].items() if result is not None]
            else:
                label_pairs = data["av_labels"]
        except KeyError:
            return None

        return SampleInfo(data['md5'], data['sha1'], data['sha256'], label_pairs) 

    @staticmethod
    def is_pup(av_label_pairs):
        '''This function classifies the sample as PUP or not 
           using the AV labels as explained in the paper:
           "Certified PUP: Abuse in Authenticode Code Signing" 
           (ACM CCS 2015)
           It uses the AV labels of 11 specific AVs. 
           The function checks for 13 keywords used to indicate PUP.
           Return:
              True/False/None
        '''
        # If no AV labels, nothing to do, return
        if not av_label_pairs:
            return None
        # Initialize
        pup = False
        threshold = 0.5
        # AVs to use
        av_set = set(['Malwarebytes', 'K7AntiVirus', 'Avast',
                  'AhnLab-V3', 'Kaspersky', 'K7GW', 'Ikarus',
                  'Fortinet', 'Antiy-AVL', 'Agnitum', 'ESET-NOD32'])
        # Tags that indicate PUP
        tags = set(['PUA', 'Adware', 'PUP', 'Unwanted', 'Riskware', 'grayware',
                    'Unwnt', 'Adknowledge', 'toolbar', 'casino', 'casonline',
                    'AdLoad', 'not-a-virus'])

        # Set with (AV name, Flagged/not flagged as PUP), for AVs in av_set
        bool_set = set([(pair[0], t.lower() in pair[1].lower()) for t in tags
                        for pair in av_label_pairs
                        if pair[0] in av_set])

        # Number of AVs that had a label for the sample
        av_detected = len([p[0] for p in av_label_pairs
                           if p[0] in av_set])

        # Number of AVs that flagged the sample as PUP
        av_pup = map(lambda x: x[1], bool_set).count(True)

        # Flag as PUP according to a threshold
        if (float(av_pup) >= float(av_detected)*threshold) and av_pup != 0:
            pup = True
        return pup


    @staticmethod
    def __remove_suffixes(av_name, label):
        '''Remove AV specific suffixes from given label
           Returns updated label'''

        # Truncate after last '.'
        if av_name in set(['Norman', 'Avast', 'Avira', 'Kaspersky',
                          'ESET-NOD32', 'Fortinet', 'Jiangmin', 'Comodo',
                          'GData', 'Avast', 'Sophos',
                          'TrendMicro-HouseCall', 'TrendMicro',
                          'NANO-Antivirus', 'Microsoft']):
            label = label.rsplit('.', 1)[0]

        # Truncate after last '.' 
        # if suffix only contains digits or uppercase (no lowercase) chars
        if av_name == 'AVG':
            tokens = label.rsplit('.', 1)
            if len(tokens) > 1 and re.match("^[A-Z0-9]+$", tokens[1]):
                label = tokens[0]

        # Truncate after last '!'
        if av_name in set(['Agnitum','McAffee','McAffee-GW-Edition']):
            label = label.rsplit('!', 1)[0]

        # Truncate after last '('
        if av_name in set(['K7AntiVirus', 'K7GW']):
            label = label.rsplit('(', 1)[0]

        # Truncate after last '@'
        # GData would belong here, but already trimmed earlier
        if av_name in set(['Ad-Aware', 'BitDefender', 'Emsisoft', 'F-Secure', 
                          'Microworld-eScan']):
            label = label.rsplit('(', 1)[0]

        return label


    def __normalize(self, label, hashes):
        '''Tokenize label, filter tokens, and replace aliases'''

        # If empty label, nothing to do
        if not label:
            return []

        # Initialize list of tokens to return
        ret = []

        # Split label into tokens and process each token
        for token in re.split("[^0-9a-zA-Z]", label):
            # Convert to lowercase
            token = token.lower()

            # Remove digits at the end
            end_len = len(re.findall("\d*$", token)[0])
            if end_len:
                token = token[:-end_len]

            # Ignore short token
            if len(token) < 4:
                continue

            # Remove generic tokens
            if token in self.gen_set:
                continue

            # Ignore token if prefix of a hash of the sample 
            # Most AVs use MD5 prefixes in labels, 
            # but we check SHA1 and SHA256 as well
            hash_token = False
            for hash_str in hashes:
                if hash_str[0:len(token)] == token:
                  hash_token = True
                  break
            if hash_token:
                continue

            # Replace alias
            token = self.aliases_map[token] if token in self.aliases_map \
                                            else token

            # Add token
            ret.append(token)
        return ret

    def get_family_ranking(self, sample_info):
        '''
        Returns sorted dictionary of most likely family names for sample
        '''
        # Extract info from named tuple
        av_label_pairs = sample_info[3]
        hashes = [ sample_info[0], sample_info[1], sample_info[2] ]

        # Whitelist the AVs to filter the ones with meaningful labels
        av_whitelist = self.avs

        # Initialize auxiliary data structures
        labels_seen = set()
        token_map = {}

        # Process each AV label
        for (av_name, label) in av_label_pairs:
            # If empty label, nothing to do
            if not label:
                continue

            ################
            # AV selection #
            ################
            if av_whitelist and av_name not in av_whitelist:
                continue

            #####################
            # Duplicate removal #
            #####################

            # If label ends in ' (B)', remove it
            if label.endswith(' (B)'):
                label = label[:-4]

            # If we have seen the label before, skip
            if label in labels_seen:
                continue
            # If not, we add it to the set of labels seen
            else:
                labels_seen.add(label)

            ##################
            # Suffix removal #
            ##################
            label = self.__remove_suffixes(av_name, label)

            ########################################################
            # Tokenization, token filtering, and alias replacement #
            ########################################################
            tokens = self.__normalize(label, hashes)

            # Increase token count in map
            for t in tokens:
                c = token_map[t] if t in token_map else 0
                token_map[t] = c + 1

        ##################################################################
        # Token ranking: sorts tokens by decreasing count and then token #
        ##################################################################
        sorted_tokens = sorted(token_map.iteritems(), 
                                key=itemgetter(1,0), 
                                reverse=True)

        # Delete the tokens appearing only in one AV, add rest to output
        sorted_dict = OrdDict()
        for t, c in sorted_tokens:
            if c > 1:
                sorted_dict[t] = c
            else:
                break
        
        return sorted_dict

