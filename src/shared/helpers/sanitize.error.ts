const sanitizeNullError = (message: string) => {
  const column = message.split('"');
  return `${column[1]} can not be null`;
};

const messageToUpper = (message: string): string => {
  const firstCharacter =
    typeof message?.split(' ')[0] === 'string'
      ? message?.split(' ')[0][0].toUpperCase() +
        message?.split(' ')[0].substring(1)
      : null;
  const finalMessage = message.split(' ');
  finalMessage[0] = firstCharacter ? firstCharacter : '';
  return finalMessage.join(' ');
};

const sanitizeFinalError = (message: string): string => {
  const splittedMessage = message.split(' ');
  if (splittedMessage.at(-1) === 'exists.') {
    message = `${splittedMessage[0]} ${splittedMessage.at(
      -2,
    )} ${splittedMessage.at(-1)}`;
  }
  return messageToUpper(message);
};

export const errorSanitizer = (message: string): string => {
  return message.includes('issue with userid,')
    ? 'An issue with a similar description already exists.'
    : message.includes('project with userid')
    ? 'A project with a similar name already exists'
    : message.includes('null value in column')
    ? sanitizeNullError(message)
    : sanitizeFinalError(message);
};
