import { shallow } from 'enzyme';
import React from 'react';
import sinon from 'sinon';
import { PageMetaContainer } from './PageMetaContainer';

describe('PageMetaContainer', () => {
  const history = {
    location: { pathname: '/' },
    listen: () => {},
  };

  it('is defined', () => {
    const wrapper = shallow(<PageMetaContainer history={history} />);
    expect(wrapper).toBeDefined();
  });

  it('stores the unlisten function returned by history.listen', () => {
    const unlisten = sinon.spy();
    const listen = sinon.stub().returns(unlisten);
    const wrapper = shallow(
      <PageMetaContainer history={{ ...history, listen }} />,
    );
    expect(listen.calledOnce).toBe(true);
    expect(wrapper.instance().unlisten).toBe(unlisten);
  });

  it('calls unlisten on unmount', () => {
    const unlisten = sinon.spy();
    const listen = sinon.stub().returns(unlisten);
    const wrapper = shallow(
      <PageMetaContainer history={{ ...history, listen }} />,
    );
    wrapper.instance().componentWillUnmount();
    expect(unlisten.calledOnce).toBe(true);
  });

  it('does not throw on unmount when unlisten is undefined', () => {
    const wrapper = shallow(<PageMetaContainer history={history} />);
    expect(() => wrapper.instance().componentWillUnmount()).not.toThrow();
  });
});
