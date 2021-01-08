from .util import get_data_file_path
import logging
from collections import OrderedDict, namedtuple
from operator import itemgetter
import re
import string
import traceback
from vt.object import Object

__all__ = ("SampleInfo",
           "LabeledSample",
           "AvLabels",)

SampleInfo = namedtuple('SampleInfo',
                        ['md5', 'sha1', 'sha256', 'labels'])

LabeledSample = namedtuple('LabeledSample',
                           ['md5', 'sha1', 'sha256', 'labels', 'family', 'tokens', 'groundtruth', 'is_pup'])


def log(message):
    print(message)


class AvLabels(object):

    def __init__(self, gen_file=None, alias_file=None, av_file=None):
        """Class to operate on AV labels, such as extracting the most likely family name.

        :param gen_file:
        :param alias_file:
        :param av_file:
        """
        # Read generic token set from file
        try:
            if gen_file is None:
                gen_file = get_data_file_path("default.generics")
            self.gen_set = self.read_generics(gen_file)
        except:
            logging.warning(traceback.format_exc())
            self.gen_set = set()

        # Read aliases map from file
        try:
            if alias_file is None:
                alias_file = get_data_file_path("default.aliases")
            self.aliases_map = self.read_aliases(alias_file)
        except:
            logging.warning(traceback.format_exc())
            self.aliases_map = {}

        # Read AV engine set from file
        self.avs = self.read_avs(av_file) if av_file else None

    @staticmethod
    def read_aliases(alfile):
        """Read aliases map from given file"""
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
        """Read generic token set from given file"""
        gen_set = set()
        with open(generics_file) as gen_fd:
            for line in gen_fd:
                if line.startswith('#') or line == '\n':
                    continue
                gen_set.add(line.strip())
        return gen_set

    @staticmethod
    def read_avs(avs_file):
        """Read AV engine set from given file"""
        with open(avs_file) as fd:
            avs = set(map(str.strip, fd.readlines()))
        return avs

    @staticmethod
    def get_sample_info(data):
        """Parse and extract sample information from JSON data
           Returns a SampleInfo named tuple: md5, sha1, sha256, label_pairs

           This method has been improved to handle multiple JSON data formats
           Recognized formats include:
           - VT File Report
           - VT Notification
           - AVClass simplified JSON
        """
        def clean(value):
            return "".join([x for x in value if x in string.printable]).strip()

        if isinstance(data, Object):
            if data.type == 'file':
                label_pairs = list(
                    map(lambda r: (r['engine_name'], clean(r['result'])),
                        filter(lambda x: x['result'] is not None,
                               data.last_analysis_results.values()))
                )
                return SampleInfo(data.md5, data.sha1, data.sha256, label_pairs)
        elif isinstance(data, dict):
            try:
                if "response_code" in data:
                    # VT file report

                    if data["response_code"] == 0:
                        return None
                    label_pairs = [(av, clean(result["result"])) for av, result in data["scans"].items() if
                                   result["result"] is not None]
                elif "ruleset_name" in data:
                    # VT notification

                    label_pairs = [(av, clean(result)) for av, result in data["scans"].items() if result is not None]
                else:
                    label_pairs = data["av_labels"]
            except KeyError:
                return None

            return SampleInfo(str(data['md5']), str(data['sha1']), str(data['sha256']), label_pairs)
        return None

    @staticmethod
    def is_pup(av_label_pairs):
        """This function classifies the sample as PUP or not
           using the AV labels as explained in the paper:
           "Certified PUP: Abuse in Authenticode Code Signing"
           (ACM CCS 2015)
           It uses the AV labels of 11 specific AVs.
           The function checks for 13 keywords used to indicate PUP.
           Return:
              True/False/None
        """
        # If no AV labels, nothing to do, return
        if not av_label_pairs:
            return None
        # Initialize
        pup = False
        threshold = 0.5
        # AVs to use
        av_set = {'Malwarebytes', 'K7AntiVirus', 'Avast', 'AhnLab-V3', 'Kaspersky', 'K7GW', 'Ikarus', 'Fortinet',
                  'Antiy-AVL', 'Agnitum', 'ESET-NOD32'}
        # Tags that indicate PUP
        tags = {'PUA', 'Adware', 'PUP', 'Unwanted', 'Riskware', 'grayware', 'Unwnt', 'Adknowledge', 'toolbar', 'casino',
                'casonline', 'AdLoad', 'not-a-virus'}

        # Set with (AV name, Flagged/not flagged as PUP), for AVs in av_set
        bool_set = set([(pair[0], t.lower() in pair[1].lower()) for t in tags
                        for pair in av_label_pairs
                        if pair[0] in av_set])

        # Number of AVs that had a label for the sample
        av_detected = len([p[0] for p in av_label_pairs
                           if p[0] in av_set])

        # Number of AVs that flagged the sample as PUP
        av_pup = list(map(lambda x: x[1], bool_set)).count(True)  # python 2/3, inefficient on Py2

        # Flag as PUP according to a threshold
        if (float(av_pup) >= float(av_detected) * threshold) and av_pup != 0:
            pup = True
        return pup

    @staticmethod
    def __remove_suffixes(av_name, label):
        """Remove AV specific suffixes from given label

        :param av_name:
        :param label:
        :return: updated label
        """

        # Truncate after last '.'
        if av_name in {'Norman', 'Avast', 'Avira', 'Kaspersky', 'ESET-NOD32', 'Fortinet', 'Jiangmin', 'Comodo', 'GData',
                       'Avast', 'Sophos', 'TrendMicro-HouseCall', 'TrendMicro', 'NANO-Antivirus', 'Microsoft'}:
            label = label.rsplit('.', 1)[0]

        # Truncate after last '.'
        # if suffix only contains digits or uppercase (no lowercase) chars
        if av_name == 'AVG':
            tokens = label.rsplit('.', 1)
            if len(tokens) > 1 and re.match("^[A-Z0-9]+$", tokens[1]):
                label = tokens[0]

        # Truncate after last '!'
        if av_name in {'Agnitum', 'McAffee', 'McAffee-GW-Edition'}:
            label = label.rsplit('!', 1)[0]

        # Truncate after last '('
        if av_name in {'K7AntiVirus', 'K7GW'}:
            label = label.rsplit('(', 1)[0]

        # Truncate after last '@'
        # GData would belong here, but already trimmed earlier
        if av_name in {'Ad-Aware', 'BitDefender', 'Emsisoft', 'F-Secure', 'Microworld-eScan'}:
            label = label.rsplit('(', 1)[0]

        return label

    def update_aliases(self, alias_file):
        try:
            alias_map = AvLabels.read_aliases(alias_file)
            self.aliases_map.update(alias_map)
        except:
            logging.warning(traceback.format_exc())

    def __normalize(self, label, hashes):
        """Tokenize label, filter tokens, and replace aliases"""

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
        """Returns sorted dictionary of most likely family names for sample

        :param sample_info:
        :return:
        """
        # Extract info from named tuple
        av_label_pairs = sample_info[3]
        hashes = [sample_info[0], sample_info[1], sample_info[2]]

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
        sorted_tokens = sorted(token_map.items(),
                               key=lambda x: x[1] or 0,
                               reverse=True)

        # Delete the tokens appearing only in one AV, add rest to output
        sorted_dict = OrderedDict()
        for t, c in sorted_tokens:
            if c > 1:
                sorted_dict[t] = c
            else:
                break

        return sorted_dict
