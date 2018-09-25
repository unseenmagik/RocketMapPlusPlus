#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time
import random
from threading import Lock
from timeit import default_timer

from .fakePogoApi import FakePogoApi
from .utils import in_radius, generate_device_info, distance
from .proxy import get_new_proxy
from .apiRequests import (send_generic_request, fort_details,
                          recycle_inventory_item, use_item_egg_incubator,
                          release_pokemon, level_up_rewards, fort_search)

log = logging.getLogger(__name__)


class TooManyLoginAttempts(Exception):
    pass


class LoginSequenceFail(Exception):
    pass


# Create the API object that'll be used to scan.
def setup_api(args, status, account):
    api = FakePogoApi(args.mock)

    return api


# Use API to check the login status, and retry the login if possible.
def check_login(args, account, api, proxy_url):
    return

# Simulate real app via login sequence.
def rpc_login_sequence(args, api, account):
    return

# Complete minimal tutorial steps.
# API argument needs to be a logged in API instance.
# TODO: Check if game client bundles these requests, or does them separately.
def complete_tutorial(args, api, account):
    return True


def reset_account(account):
    account['start_time'] = time.time()
    account['warning'] = None
    account['tutorials'] = []
    account['items'] = {}
    account['pokemons'] = {}
    account['incubators'] = []
    account['eggs'] = []
    account['level'] = 0
    account['spins'] = 0
    account['session_spins'] = 0
    account['walked'] = 0.0
    account['last_timestamp_ms'] = 0


def can_spin(account, max_h_spins):
    return False


# Check if Pokestop is spinnable and not on cooldown.
def pokestop_spinnable(fort, step_location):
    return False


def spin_pokestop(api, account, args, fort, step_location):
    return False


def parse_get_player(account, api_response):
    if 'GET_PLAYER' in api_response['responses']:
        player_data = api_response['responses']['GET_PLAYER'].player_data

        account['warning'] = api_response['responses']['GET_PLAYER'].warn
        account['tutorials'] = player_data.tutorial_state
        account['buddy'] = player_data.buddy_pokemon.id


def clear_inventory(api, account):
    return


def incubate_eggs(api, account):
    return


def parse_level_up_rewards(api, account):
    resp = level_up_rewards(api, account)
    result = resp['responses']['LEVEL_UP_REWARDS'].result
    if result == 1:
        log.info('Account %s collected its level up rewards.',
                 account['username'])
    elif result == 2:
        log.debug('Account %s already collected its level up rewards.',
                  account['username'])
    else:
        log.error('Error collecting rewards of account %s.',
                  account['username'])


# The AccountSet returns a scheduler that cycles through different
# sets of accounts (e.g. L30). Each set is defined at runtime, and is
# (currently) used to separate regular accounts from L30 accounts.
# TODO: Migrate the old account Queue to a real AccountScheduler, preferably
# handled globally via database instead of per instance.
# TODO: Accounts in the AccountSet are exempt from things like the
# account recycler thread. We could've hardcoded support into it, but that
# would have added to the amount of ugly code. Instead, we keep it as is
# until we have a proper account manager.
class AccountSet(object):

    def __init__(self, kph):
        self.sets = {}

        # Scanning limits.
        self.kph = kph

        # Thread safety.
        self.next_lock = Lock()

    # Set manipulation.
    def create_set(self, name, values=None):
        if values is None:
            values = []
        if name in self.sets:
            raise Exception('Account set ' + name + ' is being created twice.')

        self.sets[name] = values

    # Release an account back to the pool after it was used.
    def release(self, account):
        if 'in_use' not in account:
            log.error('Released account %s back to the AccountSet,'
                      + " but it wasn't locked.",
                      account['username'])
        else:
            account['in_use'] = False

    # Get next account that is ready to be used for scanning.
    def next(self, set_name, coords_to_scan):
        # Yay for thread safety.
        with self.next_lock:
            # Readability.
            account_set = self.sets[set_name]

            # Loop all accounts for a good one.
            now = default_timer()

            for i in range(len(account_set)):
                account = account_set[i]

                # Make sure it's not in use.
                if account.get('in_use', False):
                    continue

                # Make sure it's not captcha'd.
                if account.get('captcha', False):
                    continue

                # Check if we're below speed limit for account.
                last_scanned = account.get('last_scanned', False)

                if last_scanned and self.kph > 0:
                    seconds_passed = now - last_scanned
                    old_coords = account.get('last_coords', coords_to_scan)

                    distance_m = distance(old_coords, coords_to_scan)

                    cooldown_time_sec = distance_m / self.kph * 3.6

                    # Not enough time has passed for this one.
                    if seconds_passed < cooldown_time_sec:
                        continue

                # We've found an account that's ready.
                account['last_scanned'] = now
                account['last_coords'] = coords_to_scan
                account['in_use'] = True

                return account

        # TODO: Instead of returning False, return the amount of min. seconds
        # the instance needs to wait until the first account becomes available,
        # so it doesn't need to keep asking if we know we need to wait.
        return False
