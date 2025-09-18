export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text });
  const Result_1 = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  const Result_2 = IDL.Variant({ 'Ok' : IDL.Nat8, 'Err' : IDL.Text });
  const Result_3 = IDL.Variant({ 'Ok' : IDL.Vec(IDL.Text), 'Err' : IDL.Text });
  const Result_4 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Vec(IDL.Text))),
    'Err' : IDL.Text,
  });
  const Wallet = IDL.Record({
    'threshold' : IDL.Nat8,
    'metadata' : IDL.Vec(IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Text)),
    'signers' : IDL.Vec(IDL.Text),
    'message_queue' : IDL.Vec(IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Text))),
  });
  const Result_5 = IDL.Variant({ 'Ok' : IDL.Bool, 'Err' : IDL.Text });
  return IDL.Service({
    'add_metadata' : IDL.Func([IDL.Text, IDL.Text, IDL.Text], [Result], []),
    'add_signer' : IDL.Func([IDL.Text, IDL.Principal], [Result_1], []),
    'approve' : IDL.Func([IDL.Text, IDL.Text], [Result_2], []),
    'can_sign' : IDL.Func([IDL.Text, IDL.Text], [IDL.Bool], ['query']),
    'create_wallet' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Principal), IDL.Nat8],
        [Result],
        [],
      ),
    'get_messages_to_sign' : IDL.Func([IDL.Text], [Result_3], []),
    'get_messages_with_signers' : IDL.Func([IDL.Text], [Result_4], ['query']),
    'get_metadata' : IDL.Func([IDL.Text, IDL.Text], [Result_1], ['query']),
    'get_proposed_messages' : IDL.Func([IDL.Text], [Result_3], ['query']),
    'get_wallet' : IDL.Func([IDL.Text], [IDL.Opt(Wallet)], []),
    'get_wallets_for_principal' : IDL.Func(
        [IDL.Principal],
        [IDL.Vec(IDL.Text)],
        ['query'],
      ),
    'propose' : IDL.Func([IDL.Text, IDL.Text], [Result], []),
    'propose_with_metadata' : IDL.Func(
        [IDL.Text, IDL.Text, IDL.Text],
        [Result],
        [],
      ),
    'remove_signer' : IDL.Func([IDL.Text, IDL.Principal], [Result_1], []),
    'set_threshold' : IDL.Func([IDL.Text, IDL.Nat8], [Result_1], []),
    'sign' : IDL.Func([IDL.Text, IDL.Text], [Result_1], []),
    'transfer' : IDL.Func([IDL.Text, IDL.Nat64, IDL.Principal], [Result_1], []),
    'verify_signature' : IDL.Func(
        [IDL.Text, IDL.Text, IDL.Text],
        [Result_5],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return [IDL.Text]; };
