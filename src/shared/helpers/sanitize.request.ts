export const sanitizeRequest: any = (requestObject: any) => {
  Object.keys(requestObject).forEach((key) => {
    if (requestObject[key] === '' || requestObject[key] === undefined) {
      delete requestObject[key];
    }
  });
  const omit = (
    requestObject: { [x: string]: any },
    requestObjectProps: any[],
  ) => {
    requestObject = { ...requestObject };
    requestObjectProps.forEach((prop) => delete requestObject[prop]);
    return requestObject;
  };

  const newrequestObject = {};
  const attributeKeys = Object.keys(
    omit(requestObject, ['invitations', 'createdBy', 'access']),
  );
  attributeKeys.forEach((attributeKey) => {
    let attributeValue: string | boolean | number | any;
    if (requestObject[attributeKey] === false) {
      attributeValue = false;
    } else {
      attributeValue = requestObject[attributeKey];
    }
    if (attributeValue || attributeValue === false) {
      if (typeof attributeValue === 'object') {
        if (Array.isArray(attributeValue)) {
          newrequestObject[attributeKey] = requestObject[attributeKey].map(
            (value: any) => sanitizeRequest(value),
          );
        } else {
          if (isNaN(Date.parse(attributeValue))) {
            newrequestObject[attributeKey] = sanitizeRequest(attributeValue);
          } else {
            newrequestObject[attributeKey] = attributeValue;
          }
        }
      } else {
        newrequestObject[attributeKey] = attributeValue;
      }
    }
  });

  return newrequestObject;
};

export const sanitizeSaleRequest: any = (requestObject: any) => {
  Object.keys(requestObject).forEach((key) => {
    if (requestObject[key] === '' || requestObject[key] === undefined) {
      delete requestObject[key];
    }
  });
  const omit = (
    requestObject: { [x: string]: any },
    requestObjectProps: any[],
  ) => {
    requestObject = { ...requestObject };
    requestObjectProps.forEach((prop) => delete requestObject[prop]);
    return requestObject;
  };

  const newrequestObject = {};
  const attributeKeys = Object.keys(
    omit(requestObject, [
      'reference',
      'code',
      'draft',
      'description',
      'amount',
    ]),
  );
  attributeKeys.forEach((attributeKey) => {
    let attributeValue: string | boolean | number | any;
    if (requestObject[attributeKey] === false) {
      attributeValue = false;
    } else {
      attributeValue = requestObject[attributeKey];
    }
    if (attributeValue || attributeValue === false) {
      if (typeof attributeValue === 'object') {
        if (Array.isArray(attributeValue)) {
          newrequestObject[attributeKey] = requestObject[attributeKey].map(
            (value: any) => sanitizeSaleRequest(value),
          );
        } else {
          if (isNaN(Date.parse(attributeValue))) {
            newrequestObject[attributeKey] =
              sanitizeSaleRequest(attributeValue);
          } else {
            newrequestObject[attributeKey] = attributeValue;
          }
        }
      } else {
        newrequestObject[attributeKey] = attributeValue;
      }
    }
  });

  return newrequestObject;
};

export const removeDuplicates = ({ payload, key }) => {
  return payload.reduce((acc: any[], current: { [x: string]: any }) => {
    const x = acc.find(
      (item: { [x: string]: any }) => item[key] === current[key],
    );
    if (!x) {
      return acc.concat([current]);
    } else {
      return acc;
    }
  }, []);
};
